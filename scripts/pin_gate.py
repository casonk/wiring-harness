#!/usr/bin/env python3
"""PIN gate for sites fronted by the shared Caddy.

A registry entry with ``pin = true`` gets a Caddy ``forward_auth`` to this
service. Each site has its own 4-digit PIN, kept in KeePassXC and read through
the auto-pass provisioning daemon; nothing secret is stored in this repository.

Because 10,000 PINs are cheap to enumerate, the gate is built around lockouts:

* per site: too many wrong PINs lock that site, whoever asked;
* per client IP: too many wrong PINs from one address lock that address on every site.

Either lock refuses even a correct PIN until it expires. Lock durations double
each time a lock repeats and decay after a quiet day. A new lock is reported
through shock-relay on every configured channel.

Usage:
    python3 scripts/pin_gate.py serve
    python3 scripts/pin_gate.py status
    python3 scripts/pin_gate.py reset --site NAME | --ip ADDRESS | --all
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import html
import json
import logging
import logging.handlers
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

from site_registry import DEFAULT_SERVICES_TOML, load_sites

LOG = logging.getLogger("wiring-harness.pin-gate")

DEFAULT_PORT = 8781
DEFAULT_TTL_HOURS = 12.0
COOKIE_NAME = "__Host-pin"
PIN_RE = re.compile(r"\d{4}\Z")
SITE_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
UNLOCK_PATH = "/_pin/unlock"
CHANGE_PATH = "/_pin/change"
NOTICE_PATH = "/_pin/notice"
DAY = 86400
VERIFY_PATH = "/_pin/verify"
MAX_BODY = 1024
SECRET_CACHE_SECONDS = 600
SIGNING_KEY_ENTRY = "portfolio/pin-signing-key"
DEFAULT_VAULT = "infra"
CHANNELS = ("signal", "telegram", "gmail")
SERVICE_SCRIPTS = {
    "signal": "services/signal-cli/send_message.py",
    "telegram": "services/telegram/send_message.py",
    "gmail": "services/gmail-imap/send_email.py",
}


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_FILE_ENV = "WIRING_HARNESS_LOG_FILE"
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 3


def default_log_path(platform: str | None = None, env: dict[str, str] | None = None) -> Path:
    """The per-user log location each platform expects."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform == "win32":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return base / "wiring-harness" / "Logs" / "pin-gate.log"
    if platform == "darwin":
        return home / "Library" / "Logs" / "wiring-harness" / "pin-gate.log"
    state = Path(env.get("XDG_STATE_HOME") or home / ".local" / "state")
    return state / "wiring-harness" / "pin-gate.log"


def resolve_log_file(value: str | None, platform: str | None = None) -> Path | None:
    """Map ``--log-file`` / ``WIRING_HARNESS_LOG_FILE`` to a path, or None for no file.

    ``off`` disables, ``default`` is the platform location, anything else is a path, and
    ``auto`` (the unset default) writes the platform location only where there is no journal
    to read: macOS and Windows. Linux relies on the systemd journal.
    """
    raw = (value if value is not None else os.environ.get(LOG_FILE_ENV) or "auto").strip()
    lowered = raw.lower()
    platform = platform or sys.platform
    if lowered in {"", "off", "none", "0", "false"}:
        return None
    if lowered == "auto":
        return default_log_path(platform) if platform in {"win32", "darwin"} else None
    if lowered == "default":
        return default_log_path(platform)
    return Path(raw).expanduser()


class _SafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """A failed rollover (Windows refuses to rename an open file) keeps appending instead of raising."""

    def doRollover(self) -> None:  # noqa: N802 - stdlib name
        try:
            super().doRollover()
        except OSError:
            if self.stream is None:
                self.stream = self._open()


def _open_private_file(path: Path) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.parent.chmod(0o700)
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return _SafeRotatingFileHandler(path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8", delay=True)


def _mark(handler: logging.Handler, kind: str) -> logging.Handler:
    handler._pin_gate = kind  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Install stderr (and optionally rotating file) handlers once; a bad log file is never fatal."""
    name = (level or "INFO").strip().upper()
    root = logging.getLogger()
    root.setLevel(getattr(logging, name if name in LOG_LEVELS else "INFO"))
    have = {getattr(h, "_pin_gate", None) for h in root.handlers}
    if "stderr" not in have:
        root.addHandler(_mark(logging.StreamHandler(sys.stderr), "stderr"))
    path = resolve_log_file(log_file)
    if path is not None and "file" not in have:
        try:
            root.addHandler(_mark(_open_private_file(path), "file"))
        except OSError as exc:
            LOG.warning("log file %s unavailable: %s", path, exc)


# ---------------------------------------------------------------------------
# Lockout policy and state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    site_max_fails: int = 5
    ip_max_fails: int = 10
    base_lock_seconds: int = 900
    max_lock_seconds: int = 86400
    decay_seconds: int = 86400

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> Policy:
        env = os.environ if environ is None else environ
        defaults = cls()

        def number(name: str, default: int) -> int:
            raw = env.get(name, "").strip()
            return int(raw) if raw else default

        return cls(
            site_max_fails=number("WH_PIN_SITE_MAX_FAILS", defaults.site_max_fails),
            ip_max_fails=number("WH_PIN_IP_MAX_FAILS", defaults.ip_max_fails),
            base_lock_seconds=number("WH_PIN_BASE_LOCK_SECONDS", defaults.base_lock_seconds),
            max_lock_seconds=number("WH_PIN_MAX_LOCK_SECONDS", defaults.max_lock_seconds),
            decay_seconds=number("WH_PIN_DECAY_SECONDS", defaults.decay_seconds),
        )


def default_state_file() -> Path:
    if os.environ.get("WH_PIN_STATE"):
        return Path(os.environ["WH_PIN_STATE"]).expanduser()
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "wiring-harness" / "pin-gate.json"


def _blank() -> dict[str, float]:
    return {"fails": 0, "level": 0, "locked_until": 0.0, "last": 0.0}


def _fresh(entry: dict[str, float] | None, now: float, policy: Policy) -> dict[str, float]:
    """The entry, forgotten entirely once it has been quiet for the decay period."""
    if not entry:
        return _blank()
    quiet_since = max(entry.get("last", 0.0), entry.get("locked_until", 0.0))
    if now - quiet_since > policy.decay_seconds:
        return _blank()
    return {**_blank(), **entry}


def _remaining(entry: dict[str, float], now: float) -> int:
    return max(0, int(entry["locked_until"] - now + 0.999))


def _register_failure(entry: dict[str, float], now: float, max_fails: int, policy: Policy) -> int:
    """Count one failure; return the new lock length in seconds, or 0 if none was triggered."""
    entry["fails"] += 1
    entry["last"] = now
    if entry["fails"] < max_fails:
        return 0
    seconds = min(policy.base_lock_seconds * 2 ** int(entry["level"]), policy.max_lock_seconds)
    entry["level"] += 1
    entry["fails"] = 0
    entry["locked_until"] = now + seconds
    return int(seconds)


class StateStore:
    """Lockout counters in an owner-only JSON file, updated under an exclusive file lock.

    A file rather than process memory so a restart does not clear a lock and so
    ``pin_gate.py reset`` can lift one while the service runs.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    @contextlib.contextmanager
    def transaction(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if not isinstance(data, dict):
                data = {}
            data.setdefault("sites", {})
            data.setdefault("ips", {})
            data.setdefault("pins", {})
            data.setdefault("verifiers", {})
            yield data
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        finally:
            os.close(fd)

    def snapshot(self) -> dict:
        with self.transaction() as data:
            return json.loads(json.dumps(data))

    def reset(self, *, site: str | None = None, ip: str | None = None, everything: bool = False) -> int:
        removed = 0
        with self.transaction() as data:
            if everything:
                removed = len(data["sites"]) + len(data["ips"])
                data["sites"], data["ips"] = {}, {}
            if site is not None and data["sites"].pop(site, None) is not None:
                removed += 1
            if ip is not None and data["ips"].pop(ip, None) is not None:
                removed += 1
        return removed


@dataclass(frozen=True)
class Newly:
    kind: str  # "site" or "ip"
    key: str
    seconds: int


@dataclass(frozen=True)
class RotationPolicy:
    """How often PINs must change. ``max_age_days <= 0`` turns rotation off."""

    max_age_days: int = 180
    warn_days: int = 30
    allow_reuse: bool = True

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> RotationPolicy:
        env = os.environ if environ is None else environ
        defaults = cls()

        def number(name: str, default: int) -> int:
            raw = env.get(name, "").strip()
            return int(raw) if raw else default

        reuse = env.get("WH_PIN_ALLOW_REUSE", "").strip().lower()
        return cls(
            max_age_days=number("WH_PIN_ROTATE_DAYS", defaults.max_age_days),
            warn_days=number("WH_PIN_WARN_DAYS", defaults.warn_days),
            allow_reuse=defaults.allow_reuse if not reuse else reuse in {"1", "true", "yes", "on"},
        )


class Rotation:
    """When each site's PIN was last changed, and what that means today.

    A site is ``ok`` until its last 30 days, ``warn`` from then on, and ``overdue`` once the PIN is
    older than the limit. The clock starts when the gate first sees a site and restarts on every
    change made through the Change PIN page; a PIN edited directly in the vault is not noticed.
    """

    def __init__(self, store: StateStore, policy: RotationPolicy, clock=time.time) -> None:
        self.store = store
        self.policy = policy
        self.clock = clock

    @staticmethod
    def _record(data: dict, site: str, now: float) -> dict:
        return data["pins"].setdefault(site, {"changed": now})

    def _classify(self, changed: float, now: float) -> tuple[str, int]:
        if self.policy.max_age_days <= 0:
            return "ok", 10**6
        due = changed + self.policy.max_age_days * DAY
        days_left = math.ceil((due - now) / DAY)
        if now >= due:
            return "overdue", days_left
        if due - now <= self.policy.warn_days * DAY:
            return "warn", days_left
        return "ok", days_left

    def status(self, site: str) -> tuple[str, int]:
        """(``ok`` | ``warn`` | ``overdue``, whole days until the PIN is due; zero or less once overdue)."""
        now = self.clock()
        with self.store.transaction() as data:
            record = self._record(data, site, now)
            return self._classify(record["changed"], now)

    def ensure(self, sites) -> None:
        now = self.clock()
        with self.store.transaction() as data:
            for site in sites:
                self._record(data, site, now)

    def record_change(self, site: str) -> None:
        with self.store.transaction() as data:
            data["pins"][site] = {"changed": self.clock()}

    def due_notices(self, sites) -> list[tuple[str, str, int]]:
        """Notices not yet sent for this PIN: (site, ``warn`` | ``overdue``, days left). Marks them sent."""
        now = self.clock()
        notices: list[tuple[str, str, int]] = []
        with self.store.transaction() as data:
            for site in sites:
                record = self._record(data, site, now)
                state, days = self._classify(record["changed"], now)
                if state == "overdue" and "overdue_sent" not in record:
                    record["overdue_sent"] = now
                    notices.append((site, "overdue", days))
                elif state == "warn" and "warn_sent" not in record:
                    record["warn_sent"] = now
                    notices.append((site, "warn", days))
        return notices


class Lockouts:
    def __init__(self, store: StateStore, policy: Policy, clock=time.time) -> None:
        self.store = store
        self.policy = policy
        self.clock = clock

    def locked_for(self, site: str, ip: str) -> int:
        """Seconds until the longer of the site and IP locks expires; 0 when neither holds."""
        now = self.clock()
        with self.store.transaction() as data:
            site_entry = _fresh(data["sites"].get(site), now, self.policy)
            ip_entry = _fresh(data["ips"].get(ip), now, self.policy)
        return max(_remaining(site_entry, now), _remaining(ip_entry, now))

    def record_failure(self, site: str, ip: str) -> list[Newly]:
        now = self.clock()
        triggered: list[Newly] = []
        with self.store.transaction() as data:
            for kind, bucket, key, limit in (
                ("site", "sites", site, self.policy.site_max_fails),
                ("ip", "ips", ip, self.policy.ip_max_fails),
            ):
                entry = _fresh(data[bucket].get(key), now, self.policy)
                seconds = _register_failure(entry, now, limit, self.policy)
                data[bucket][key] = entry
                if seconds:
                    triggered.append(Newly(kind, key, seconds))
        return triggered

    def record_success(self, site: str) -> None:
        # Only the site's own counters clear. A correct PIN must not wipe the client's
        # failures, or knowing one PIN would let an attacker keep guessing at the others.
        with self.store.transaction() as data:
            data["sites"].pop(site, None)


# ---------------------------------------------------------------------------
# Secrets, cookies
# ---------------------------------------------------------------------------


class SecretError(RuntimeError):
    """A secret could not be read; the gate fails closed.

    ``reason`` says why, so the browser and the log never blame the vault for a missing
    binary: ``locked`` (vault locked), ``missing`` (auto-pass not runnable), ``denied``
    (request refused or entry absent) or ``error`` (anything else).
    """

    def __init__(self, message: str, reason: str = "error") -> None:
        super().__init__(message)
        self.reason = reason


UNAVAILABLE_BODIES = {
    "locked": b"PIN check unavailable: the auto-pass vault is locked",
    "missing": b"PIN check unavailable: the auto-pass command was not found by the PIN gate",
    "denied": b"PIN check unavailable: auto-pass refused the request",
    "error": b"PIN check unavailable: secrets could not be read (see the PIN gate log)",
}


class AutoPassSecrets:
    """Reads secrets through the auto-pass provisioning daemon, caching them briefly."""

    def __init__(
        self,
        command: str = "auto-pass",
        vault: str = DEFAULT_VAULT,
        ttl: int = SECRET_CACHE_SECONDS,
        clock=time.monotonic,
    ) -> None:
        self.command = command
        self.vault = vault
        self.ttl = ttl
        self.clock = clock
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, entry: str) -> str:
        with self._lock:
            cached = self._cache.get(entry)
            if cached and self.clock() - cached[0] < self.ttl:
                return cached[1]
        try:
            result = subprocess.run(
                [self.command, "provision-get", "--db", self.vault, entry],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            reason = "missing" if isinstance(exc, FileNotFoundError) else "error"
            raise SecretError(f"auto-pass unavailable ({self.command!r}): {exc}", reason) from exc
        value = result.stdout.strip("\r\n")
        if result.returncode != 0 or not value:
            detail = (result.stderr or "").strip().splitlines()[-1:] or [""]
            reason = "locked" if "locked" in detail[0].lower() else "denied"
            raise SecretError(f"auto-pass could not provide {entry!r} ({reason}): {detail[0][:200]}", reason)
        with self._lock:
            self._cache[entry] = (self.clock(), value)
        return value

    def set(self, entry: str, value: str) -> None:
        """Replace an existing entry's password through the daemon's scoped `set` operation."""
        try:
            from auto_pass.client import ProvisioningClient, ProvisioningClientError
        except ImportError as exc:
            raise SecretError("auto_pass is not importable; cannot change a PIN") from exc
        try:
            ProvisioningClient().set(entry, value, db=self.vault)
        except (OSError, ProvisioningClientError) as exc:
            raise SecretError(f"auto-pass refused to change {entry!r}: {exc}") from exc
        with self._lock:
            self._cache.pop(entry, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


def _site_key(signing_key: str, site: str, pin: str) -> bytes:
    """A per-site key that also depends on the PIN, so changing a PIN revokes its cookies."""
    return hmac.new(signing_key.encode(), f"pin-gate:{site}:{pin}".encode(), hashlib.sha256).digest()


def make_cookie_value(signing_key: str, site: str, pin: str, expires: int) -> str:
    mac = hmac.new(_site_key(signing_key, site, pin), f"{site}|{expires}".encode(), hashlib.sha256)
    return f"{site}.{expires}.{mac.hexdigest()}"


def cookie_valid(value: str, signing_key: str, site: str, pin: str, now: float) -> bool:
    try:
        cookie_site, expires_text, signature = value.split(".")
        expires = int(expires_text)
    except ValueError:
        return False
    if cookie_site != site or expires <= now:
        return False
    expected = make_cookie_value(signing_key, site, pin, expires).rsplit(".", 1)[1]
    return hmac.compare_digest(signature, expected)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class Notifier:
    """Reports a new lock through shock-relay on every configured channel, off the request path."""

    def __init__(self, root: Path, targets: dict[str, tuple[str, str | None]]) -> None:
        self.root = root
        self.targets = targets

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> Notifier:
        env = os.environ if environ is None else environ
        root = Path(env.get("WH_PIN_SHOCK_RELAY_ROOT") or Path(__file__).resolve().parents[2] / "shock-relay")
        targets: dict[str, tuple[str, str | None]] = {}
        for channel in CHANNELS:
            target = env.get(f"WH_PIN_NOTIFY_{channel.upper()}_TARGET", "").strip()
            if target:
                targets[channel] = (target, env.get(f"WH_PIN_NOTIFY_{channel.upper()}_CONFIG") or None)
        if not targets:
            LOG.warning("no WH_PIN_NOTIFY_*_TARGET set; PIN lockouts will not be reported")
        return cls(root, targets)

    def notify(self, event: Newly) -> None:
        threading.Thread(target=self._send_all, args=(event,), daemon=True).start()

    def announce(self, subject: str, body: str) -> None:
        """Send a message to every channel off the request path (never carries a PIN)."""
        threading.Thread(target=self._deliver, args=(subject, body), daemon=True).start()

    def _send_all(self, event: Newly) -> None:
        minutes = max(1, round(event.seconds / 60))
        self._deliver(
            f"wiring-harness: PIN lockout ({event.kind})",
            f"Too many wrong PINs for {event.kind} {event.key}; locked for {minutes} min.",
        )

    def _deliver(self, subject: str, body: str) -> None:
        for channel, (target, config) in self.targets.items():
            try:
                self._send(channel, target, config, subject, body)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                LOG.warning("notification via %s failed: %s", channel, exc)

    def _send(self, channel: str, target: str, config: str | None, subject: str, body: str) -> None:
        script = self.root / SERVICE_SCRIPTS[channel]
        if not script.exists():
            raise RuntimeError(f"shock-relay script not found: {script}")
        if channel == "gmail":
            command = [sys.executable, str(script), target, subject, body]
        else:
            command = [sys.executable, str(script), target, f"{subject}\n{body}"]
        if config:
            command += ["--config", config]
        env = {**os.environ, "PYTHONPATH": str(script.parent)}
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env, check=False)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout).strip() or f"exit {result.returncode}")


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SiteConfig:
    name: str
    entry: str
    ttl_seconds: int


def sites_from_registry(services_path: Path) -> dict[str, SiteConfig]:
    configs: dict[str, SiteConfig] = {}
    for site in load_sites(services_path):
        if not site.get("pin"):
            continue
        name = site["name"]
        hours = float(site.get("pin_ttl_hours", DEFAULT_TTL_HOURS))
        configs[name] = SiteConfig(name, site.get("pin_entry") or f"portfolio/pin/{name}", int(hours * 3600))
    return configs


def weak_pin(pin: str) -> bool:
    """Repeated digits (0000) or a straight run up or down (1234, 8765) are the first guesses."""
    digits = [int(ch) for ch in pin]
    steps = {b - a for a, b in zip(digits, digits[1:], strict=False)}
    return len(set(digits)) == 1 or steps in ({1}, {-1})


def safe_next(value: str | None) -> str:
    """Only a same-site absolute path may be redirected to after unlocking."""
    if not value or not value.startswith("/") or value.startswith("//") or value.startswith(UNLOCK_PATH):
        return "/"
    if any(ch in value for ch in "\\\r\n") or any(ord(ch) < 32 for ch in value):
        return "/"
    return value


def same_origin_post(headers) -> bool:
    """Whether a POST came from this site's own pages.

    The sites send ``Referrer-Policy: no-referrer``, and browsers then put ``Origin: null`` on even
    same-origin form posts, so ``null`` must not be treated as foreign. ``Sec-Fetch-Site`` is the
    reliable signal where present (browsers set it, pages cannot forge it): only ``same-origin`` passes.
    Without it, a named Origin must match the Host.
    """
    fetch_site = headers.get("Sec-Fetch-Site")
    if fetch_site:
        return fetch_site == "same-origin"
    origin = headers.get("Origin")
    if not origin or origin == "null":
        return True
    return origin.split("://", 1)[-1] == headers.get("Host", "")


def client_ip(headers) -> str:
    # Caddy replaces X-Forwarded-For for untrusted clients and this service binds loopback only,
    # so the last hop is the address Caddy actually saw.
    forwarded = headers.get("X-Forwarded-For", "")
    last = forwarded.split(",")[-1].strip()
    return last or "unknown"


class Seal:
    """A TPM-sealed key that lets the gate check PINs while the vault is locked.

    systemd unseals the key (a ``LoadCredentialEncrypted`` credential bound to the TPM) for the
    service only. From it the gate derives a keyed fingerprint of each PIN, ``HMAC(key, site|pin)``,
    and the cookie-signing key. The fingerprints are kept in the state file: without the sealed
    key, which never leaves the TPM at rest, ten thousand guesses cannot be tried offline. The
    vault stays the source of truth and is read only to refresh the fingerprints and to change a PIN.
    """

    CREDENTIAL = "pin-seal-key"

    def __init__(self, key: bytes, store: StateStore) -> None:
        self._key = key
        self.store = store

    @classmethod
    def from_environment(cls, store: StateStore, environ: dict[str, str] | None = None) -> Seal | None:
        env = os.environ if environ is None else environ
        path = env.get("WH_PIN_SEAL_KEY_FILE", "").strip()
        if not path and env.get("CREDENTIALS_DIRECTORY"):
            path = str(Path(env["CREDENTIALS_DIRECTORY"]) / cls.CREDENTIAL)
        if not path:
            return None
        try:
            key = Path(path).read_bytes().strip()
        except OSError as exc:
            LOG.warning("sealed key %s unreadable (%s); using the vault for every check", path, exc)
            return None
        if len(key) < 16:
            LOG.warning("sealed key %s is too short; using the vault for every check", path)
            return None
        return cls(key, store)

    def compute(self, site: str, pin: str) -> str:
        return hmac.new(self._key, f"pin-verifier:{site}:{pin}".encode(), hashlib.sha256).hexdigest()

    def cookie_key(self) -> str:
        return hmac.new(self._key, b"cookie-signing:v1", hashlib.sha256).hexdigest()

    def verifier_for(self, site: str) -> str | None:
        with self.store.transaction() as data:
            record = data["verifiers"].get(site)
        return record.get("v") if isinstance(record, dict) else None

    def remember(self, site: str, pin: str, now: float) -> str | None:
        """Store this PIN's fingerprint; return the previous one (None if there was none)."""
        verifier = self.compute(site, pin)
        with self.store.transaction() as data:
            previous = (data["verifiers"].get(site) or {}).get("v")
            data["verifiers"][site] = {"v": verifier, "synced": now}
        return previous


@dataclass(frozen=True)
class SiteSecret:
    """What the gate needs to judge a guess and bind a cookie to the current PIN."""

    matches: Callable[[str], bool]
    binder: str
    signing_key: str


class Gate:
    def __init__(
        self,
        sites: dict[str, SiteConfig],
        secrets: AutoPassSecrets,
        lockouts: Lockouts,
        notifier: Notifier,
        signing_key_entry: str = SIGNING_KEY_ENTRY,
        clock=time.time,
        rotation: Rotation | None = None,
        seal: Seal | None = None,
    ) -> None:
        self.seal = seal
        self.rotation = rotation or Rotation(lockouts.store, RotationPolicy(), clock)
        self.sites = sites
        self.secrets = secrets
        self.lockouts = lockouts
        self.notifier = notifier
        self.signing_key_entry = signing_key_entry
        self.clock = clock

    def _material(self, site: SiteConfig) -> SiteSecret:
        """The sealed fingerprint when there is one, else the vault, so a locked vault does not stop the gate."""
        if self.seal is not None:
            verifier = self.seal.verifier_for(site.name)
            if verifier:
                seal = self.seal

                def sealed_match(guess: str) -> bool:
                    return bool(PIN_RE.match(guess or "")) and hmac.compare_digest(
                        seal.compute(site.name, guess), verifier
                    )

                return SiteSecret(sealed_match, verifier, seal.cookie_key())
        pin = self.secrets.get(site.entry)
        key = self.secrets.get(self.signing_key_entry)

        def vault_match(guess: str) -> bool:
            return bool(PIN_RE.match(guess or "")) and hmac.compare_digest(guess.encode(), pin.encode())

        return SiteSecret(vault_match, pin, key)

    def has_valid_cookie(self, site: SiteConfig, cookie_header: str) -> bool:
        value = _cookie(cookie_header, COOKIE_NAME)
        if not value:
            return False
        if self.rotation.status(site.name)[0] == "overdue":
            return False  # an expired PIN ends existing sessions too
        material = self._material(site)
        return cookie_valid(value, material.signing_key, site.name, material.binder, self.clock())

    def _check_current(self, site: SiteConfig, ip: str, guess: str) -> tuple[str, int, SiteSecret | None]:
        """Check a PIN against the lockouts. Returns (outcome, lock_seconds, secret when it matched)."""
        remaining = self.lockouts.locked_for(site.name, ip)
        if remaining:
            LOG.info("refused attempt on %s from %s: locked for %ss", site.name, ip, remaining)
            return "locked", remaining, None
        material = self._material(site)
        if material.matches(guess):
            self.lockouts.record_success(site.name)
            return "ok", 0, material
        for event in self.lockouts.record_failure(site.name, ip):
            LOG.warning(
                "lockout: %s %s for %ss (attempt on %s from %s)", event.kind, event.key, event.seconds, site.name, ip
            )
            self.notifier.notify(event)
        LOG.info("wrong PIN on %s from %s", site.name, ip)
        return "wrong", self.lockouts.locked_for(site.name, ip), None

    def _new_cookie(self, site: SiteConfig, binder: str, key: str) -> str:
        return make_cookie_value(key, site.name, binder, int(self.clock()) + site.ttl_seconds)

    def sync_sealed(self) -> int:
        """Refresh the sealed fingerprints from the vault when it is reachable; returns how many changed.

        A fingerprint that differs from one already stored means the PIN was edited in the vault
        directly, which counts as a change: the rotation clock restarts and old sessions end.
        """
        if self.seal is None:
            return 0
        changed = 0
        for site in self.sites.values():
            try:
                pin = self.secrets.get(site.entry)
            except SecretError:
                continue  # vault locked or entry missing: keep what we have
            if not PIN_RE.match(pin):
                LOG.warning("vault PIN for %s is not four digits; not sealing it", site.name)
                continue
            previous = self.seal.remember(site.name, pin, self.clock())
            if previous != self.seal.compute(site.name, pin):
                changed += 1
                if previous is not None:
                    self.rotation.record_change(site.name)
                    LOG.warning("PIN for %s was changed in the vault; rotation clock restarted", site.name)
        return changed

    def attempt(self, site: SiteConfig, ip: str, guess: str) -> tuple[str, int, str | None]:
        """Returns (outcome, lock_seconds, cookie). Outcome: ok, wrong, or locked."""
        outcome, seconds, material = self._check_current(site, ip, guess)
        if material is None:
            return outcome, seconds, None
        if self.rotation.status(site.name)[0] == "overdue":
            LOG.info("correct PIN for %s from %s but it has expired; change required", site.name, ip)
            return "expired", 0, None
        LOG.info("unlocked %s for %s", site.name, ip)
        return "ok", 0, self._new_cookie(site, material.binder, material.signing_key)

    def change_pin(
        self, site: SiteConfig, ip: str, current: str, new: str, confirm: str
    ) -> tuple[str, int, str | None]:
        """Change a site's PIN. Outcome: ok, wrong, locked, mismatch, weak, same or unavailable.

        The current PIN is checked first and counts toward the same lockouts as unlocking, so this
        form cannot be used to guess it. Only then is the new value judged, and only a value that
        passes is written. Cookies are tied to the PIN, so every other device is signed out; the
        caller gets a fresh cookie so this one stays unlocked.
        """
        outcome, seconds, material = self._check_current(site, ip, current)
        if material is None:
            return outcome, seconds, None
        if not PIN_RE.match(new or "") or new != confirm:
            return "mismatch", 0, None
        if weak_pin(new):
            return "weak", 0, None
        if material.matches(new):
            if not self.rotation.policy.allow_reuse:
                return "same", 0, None
            # Reuse is allowed for now: nothing to write, but the rotation clock restarts.
            self.rotation.record_change(site.name)
            LOG.warning("PIN for %s renewed unchanged from %s", site.name, ip)
            self.notifier.announce("wiring-harness: PIN renewed", f"The PIN for {site.name} was renewed from {ip}.")
            return "ok", 0, self._new_cookie(site, material.binder, material.signing_key)
        try:
            self.secrets.set(site.entry, new)
            if self.secrets.get(site.entry) != new:
                raise SecretError("the stored PIN does not match what was written")
        except SecretError as exc:
            LOG.error("PIN change for %s failed: %s", site.name, exc)
            return "unavailable", 0, None
        self.rotation.record_change(site.name)
        if self.seal is not None:
            self.seal.remember(site.name, new, self.clock())
        LOG.warning("PIN for %s changed from %s; other devices are signed out", site.name, ip)
        self.notifier.announce("wiring-harness: PIN changed", f"The PIN for {site.name} was changed from {ip}.")
        fresh = self._material(site)
        return "ok", 0, self._new_cookie(site, fresh.binder, fresh.signing_key)

    def send_rotation_notices(self) -> int:
        """Announce each PIN that has entered its warning window or gone overdue, once."""
        notices = self.rotation.due_notices(self.sites)
        for site, kind, days in notices:
            if kind == "overdue":
                subject = "wiring-harness: PIN expired"
                body = f"The PIN for {site} is past its rotation limit. Opening the site now requires changing it."
            else:
                subject = "wiring-harness: PIN due for rotation"
                body = f"The PIN for {site} must be changed within {max(days, 0)} day{'s' if days != 1 else ''}."
            LOG.warning("rotation notice for %s: %s (%s days)", site, kind, days)
            self.notifier.announce(subject, body)
        return len(notices)


def _cookie(header: str, name: str) -> str | None:
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Unlock</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;
background:var(--bg,#0f1218);color:var(--fg,#e8ecf2)}}
form{{text-align:center;padding:2rem;background:var(--surface,#181d27);border-radius:12px;min-width:16rem}}
input[type=password]{{font:2rem monospace;letter-spacing:.6rem;width:8rem;text-align:center;padding:.4rem;
border-radius:8px;border:1px solid var(--border,#3a4254);background:transparent;color:inherit}}
button{{margin-top:1rem;padding:.6rem 1.6rem;border-radius:8px;border:0;background:var(--accent,#4c8dff);
color:#fff;font:inherit}}
p{{margin:.8rem 0 0}} .err{{color:var(--danger,#ff6b6b)}}
</style></head><body>
<form method="post" action="{action}">
<h1 style="font-size:1.1rem;margin:0 0 1rem">Enter PIN</h1>
<input type="password" name="pin" inputmode="numeric" pattern="[0-9]{{4}}" maxlength="4"
 autocomplete="off" autofocus required>
<input type="hidden" name="next" value="{next}">
<div><button type="submit">Unlock</button></div>
{message}
<p><a href="{change}" style="color:inherit;font-size:.85rem">Change PIN</a></p>
</form></body></html>
"""

CHANGE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Change PIN</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;
background:var(--bg,#0f1218);color:var(--fg,#e8ecf2)}}
form{{text-align:center;padding:2rem;background:var(--surface,#181d27);border-radius:12px;min-width:16rem}}
label{{display:block;margin-top:1rem;font-size:.85rem;text-align:left}}
input[type=password]{{font:1.6rem monospace;letter-spacing:.5rem;width:100%;box-sizing:border-box;text-align:center;
padding:.3rem;border-radius:8px;border:1px solid var(--border,#3a4254);background:transparent;color:inherit}}
button{{margin-top:1.2rem;padding:.6rem 1.6rem;border-radius:8px;border:0;background:var(--accent,#4c8dff);
color:#fff;font:inherit}}
p{{margin:.8rem 0 0}} .err{{color:var(--danger,#ff6b6b)}}
</style></head><body>
<form method="post" action="{action}">
<h1 style="font-size:1.1rem;margin:0">Change PIN</h1>
<label>Current PIN<input type="password" name="current" inputmode="numeric" pattern="[0-9]{{4}}"
 maxlength="4" autocomplete="off" autofocus required></label>
<label>New PIN<input type="password" name="new" inputmode="numeric" pattern="[0-9]{{4}}"
 maxlength="4" autocomplete="off" required></label>
<label>New PIN again<input type="password" name="confirm" inputmode="numeric" pattern="[0-9]{{4}}"
 maxlength="4" autocomplete="off" required></label>
<input type="hidden" name="next" value="{next}">
<div><button type="submit">Change PIN</button></div>
{message}
<p><a href="{unlock}" style="color:inherit;font-size:.85rem">Back</a></p>
</form></body></html>
"""


def render_page(next_path: str, message: str = "", error: bool = False) -> bytes:
    note = f'<p class="{"err" if error else ""}">{html.escape(message)}</p>' if message else ""
    return PAGE.format(
        action=UNLOCK_PATH, change=CHANGE_PATH, next=html.escape(next_path, quote=True), message=note
    ).encode()


def render_change_page(next_path: str, message: str = "", error: bool = False) -> bytes:
    note = f'<p class="{"err" if error else ""}">{html.escape(message)}</p>' if message else ""
    return CHANGE_PAGE.format(
        action=CHANGE_PATH, unlock=UNLOCK_PATH, next=html.escape(next_path, quote=True), message=note
    ).encode()


NOTICE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PIN due for rotation</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;
background:var(--bg,#0f1218);color:var(--fg,#e8ecf2)}}
main{{text-align:center;padding:2rem;background:var(--surface,#181d27);border-radius:12px;max-width:22rem}}
a.btn{{display:inline-block;margin:.4rem;padding:.6rem 1.4rem;border-radius:8px;text-decoration:none;
background:var(--accent,#4c8dff);color:#fff}}
a.quiet{{background:transparent;border:1px solid var(--border,#3a4254);color:inherit}}
</style></head><body><main>
<h1 style="font-size:1.1rem;margin:0 0 .8rem">Your PIN is due for rotation</h1>
<p>{message}</p>
<a class="btn" href="{change}">Change PIN now</a>
<a class="btn quiet" href="{next}">Remind me later</a>
</main></body></html>
"""


def render_notice_page(next_path: str, days_left: int) -> bytes:
    days = max(days_left, 0)
    message = (
        f"It must be changed within {days} day{'s' if days != 1 else ''}, after which this site will ask for a new one."
    )
    return NOTICE_PAGE.format(
        message=html.escape(message),
        change=f"{CHANGE_PATH}?next={quote(next_path, safe='/')}",
        next=html.escape(next_path, quote=True),
    ).encode()


EXPIRED_MESSAGE = "Your PIN has expired. Enter it once more and choose a new one to continue."

CHANGE_MESSAGES = {
    "wrong": "Incorrect current PIN.",
    "mismatch": "The new PIN must be four digits, entered the same way twice.",
    "same": "The new PIN must differ from the current one.",
    "weak": "Too easy to guess: avoid repeated digits and runs such as 1234.",
    "unavailable": "The PIN could not be changed and is unchanged. Try again later.",
}


def lock_message(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return f"Too many attempts. Try again in about {minutes} minute{'s' if minutes != 1 else ''}."


def make_handler(gate: Gate):
    class Handler(BaseHTTPRequestHandler):
        server_version = "pin-gate"
        sys_version = ""

        def log_message(self, fmt, *args):  # route access logs through logging, never print PINs
            LOG.debug("%s %s", self.address_string(), fmt % args)

        # -- helpers -----------------------------------------------------
        def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            if body:
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header(
                    "Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
                )
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def _site(self) -> SiteConfig | None:
            name = self.headers.get("X-Pin-Site", "")
            site = gate.sites.get(name) if SITE_RE.match(name) else None
            if site is None:
                LOG.warning("request for unknown PIN site %r", name)
                self._send(HTTPStatus.BAD_REQUEST, b"unknown site")
            return site

        def _redirect_to_unlock(self, next_path: str) -> None:
            self._send(HTTPStatus.SEE_OTHER, headers={"Location": f"{UNLOCK_PATH}?next={quote(next_path, safe='/')}"})

        # -- routes ------------------------------------------------------
        def do_GET(self):  # noqa: N802
            path, _, query = self.path.partition("?")
            site = self._site()
            if site is None:
                return
            if path == VERIFY_PATH:
                return self._verify(site)
            if path == UNLOCK_PATH:
                next_path = safe_next(parse_qs(query).get("next", [""])[0])
                remaining = gate.lockouts.locked_for(site.name, client_ip(self.headers))
                message = lock_message(remaining) if remaining else ""
                return self._send(HTTPStatus.OK, render_page(next_path, message, error=bool(remaining)))
            if path == CHANGE_PATH:
                params = parse_qs(query)
                next_path = safe_next(params.get("next", [""])[0])
                remaining = gate.lockouts.locked_for(site.name, client_ip(self.headers))
                if remaining:
                    return self._send(HTTPStatus.OK, render_change_page(next_path, lock_message(remaining), True))
                expired = params.get("reason", [""])[0] == "expired"
                return self._send(
                    HTTPStatus.OK, render_change_page(next_path, EXPIRED_MESSAGE if expired else "", error=expired)
                )
            if path == NOTICE_PATH:
                return self._notice(site, safe_next(parse_qs(query).get("next", [""])[0]))
            self._send(HTTPStatus.NOT_FOUND, b"not found")

        do_HEAD = do_GET  # noqa: N815

        def _notice(self, site: SiteConfig, next_path: str) -> None:
            try:
                unlocked = gate.has_valid_cookie(site, self.headers.get("Cookie", ""))
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, UNAVAILABLE_BODIES.get(exc.reason, UNAVAILABLE_BODIES["error"]))
            if not unlocked:
                return self._redirect_to_unlock(next_path)
            state, days = gate.rotation.status(site.name)
            if state != "warn":
                return self._send(HTTPStatus.SEE_OTHER, headers={"Location": next_path})
            self._send(HTTPStatus.OK, render_notice_page(next_path, days))

        def _verify(self, site: SiteConfig) -> None:
            try:
                valid = gate.has_valid_cookie(site, self.headers.get("Cookie", ""))
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, UNAVAILABLE_BODIES.get(exc.reason, UNAVAILABLE_BODIES["error"]))
            if valid:
                return self._send(HTTPStatus.NO_CONTENT)
            original = self.headers.get("X-Forwarded-Uri", "/")
            if self.headers.get("X-Forwarded-Method", "GET") in {"GET", "HEAD"}:
                return self._redirect_to_unlock(safe_next(original))
            self._send(HTTPStatus.UNAUTHORIZED, b"PIN required")

        def _change(self, site: SiteConfig, form: dict, next_path: str) -> None:
            def field(name: str) -> str:
                return form.get(name, [""])[0]

            try:
                outcome, seconds, cookie = gate.change_pin(
                    site, client_ip(self.headers), field("current"), field("new"), field("confirm")
                )
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, UNAVAILABLE_BODIES.get(exc.reason, UNAVAILABLE_BODIES["error"]))
            if outcome == "ok":
                attrs = f"{COOKIE_NAME}={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={site.ttl_seconds}"
                return self._send(HTTPStatus.SEE_OTHER, headers={"Location": next_path, "Set-Cookie": attrs})
            if outcome == "locked" or seconds:
                return self._send(
                    HTTPStatus.TOO_MANY_REQUESTS, render_change_page(next_path, lock_message(seconds), True)
                )
            status = HTTPStatus.SERVICE_UNAVAILABLE if outcome == "unavailable" else HTTPStatus.UNAUTHORIZED
            if outcome in {"mismatch", "same", "weak"}:
                status = HTTPStatus.UNPROCESSABLE_ENTITY
            self._send(status, render_change_page(next_path, CHANGE_MESSAGES[outcome], True))

        def do_POST(self):  # noqa: N802
            path = self.path.partition("?")[0]
            site = self._site()
            if site is None:
                return
            if path not in (UNLOCK_PATH, CHANGE_PATH):
                return self._send(HTTPStatus.NOT_FOUND, b"not found")
            if not same_origin_post(self.headers):
                LOG.warning("cross-origin unlock attempt on %s refused", site.name)
                return self._send(HTTPStatus.FORBIDDEN, b"cross-origin request refused")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"too large")
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            next_path = safe_next(form.get("next", [""])[0])
            if path == CHANGE_PATH:
                return self._change(site, form, next_path)
            guess = form.get("pin", [""])[0]
            try:
                outcome, seconds, cookie = gate.attempt(site, client_ip(self.headers), guess)
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, UNAVAILABLE_BODIES.get(exc.reason, UNAVAILABLE_BODIES["error"]))
            if outcome == "expired":
                target = f"{CHANGE_PATH}?reason=expired&next={quote(next_path, safe='/')}"
                return self._send(HTTPStatus.SEE_OTHER, headers={"Location": target})
            if outcome == "ok":
                attrs = f"{COOKIE_NAME}={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={site.ttl_seconds}"
                target = next_path
                if gate.rotation.status(site.name)[0] == "warn":
                    target = f"{NOTICE_PATH}?next={quote(next_path, safe='/')}"
                return self._send(HTTPStatus.SEE_OTHER, headers={"Location": target, "Set-Cookie": attrs})
            if outcome == "locked" or seconds:
                return self._send(HTTPStatus.TOO_MANY_REQUESTS, render_page(next_path, lock_message(seconds), True))
            self._send(HTTPStatus.UNAUTHORIZED, render_page(next_path, "Incorrect PIN.", True))

    return Handler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _watch_rotation(gate: Gate, interval: int = 3600) -> None:
    """Hourly: announce PINs entering their warning window or going overdue."""
    while True:
        try:
            gate.sync_sealed()
            gate.send_rotation_notices()
        except Exception:  # keep the watcher alive; one failed pass must not end the notices
            LOG.warning("rotation notice pass failed", exc_info=True)
        time.sleep(interval)


def _cmd_serve(args: argparse.Namespace) -> int:
    sites = sites_from_registry(Path(args.services))
    if not sites:
        LOG.error("no sites with pin = true in %s", args.services)
        return 1
    store = StateStore(default_state_file())
    gate = Gate(
        sites,
        AutoPassSecrets(vault=os.environ.get("WH_PIN_VAULT", DEFAULT_VAULT)),
        Lockouts(store, Policy.from_env()),
        Notifier.from_env(),
        signing_key_entry=os.environ.get("WH_PIN_SIGNING_KEY_ENTRY", SIGNING_KEY_ENTRY),
        rotation=Rotation(store, RotationPolicy.from_env()),
        seal=Seal.from_environment(store),
    )
    gate.rotation.ensure(sites)
    if shutil.which(gate.secrets.command) is None:
        LOG.error(
            "auto-pass command %r not found on PATH=%s: PIN checks that need the vault will fail",
            gate.secrets.command,
            os.environ.get("PATH", ""),
        )
    if gate.seal is None:
        LOG.warning("no sealed key: every PIN check needs the auto-pass vault unlocked")
    else:
        LOG.info("sealed key loaded; refreshed %d fingerprint(s) from the vault", gate.sync_sealed())
    threading.Thread(target=_watch_rotation, args=(gate,), daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(gate))
    LOG.info("PIN gate on 127.0.0.1:%d for %s", args.port, ", ".join(sorted(sites)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    now = time.time()
    snapshot = StateStore(default_state_file()).snapshot()
    policy = Policy.from_env()
    rows = 0
    for bucket, label in (("sites", "site"), ("ips", "ip")):
        for key, raw in sorted(snapshot[bucket].items()):
            entry = _fresh(raw, now, policy)
            remaining = _remaining(entry, now)
            if remaining or entry["fails"]:
                rows += 1
                print(
                    f"{label} {key}: {int(entry['fails'])} failures, locked {remaining}s, level {int(entry['level'])}"
                )
    if not rows:
        print("no active lockouts or failure counts")
    print(f"sealed fingerprints stored: {len(snapshot.get('verifiers', {}))}")
    rotation = Rotation(StateStore(default_state_file()), RotationPolicy.from_env())
    for name in sorted(snapshot.get("pins", {})):
        state, days = rotation.status(name)
        print(f"pin {name}: {state}, {days} days until due")
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    if not (args.site or args.ip or args.all):
        print("error: give --site, --ip, or --all", file=sys.stderr)
        return 2
    removed = StateStore(default_state_file()).reset(site=args.site, ip=args.ip, everything=args.all)
    print(f"cleared {removed} record{'s' if removed != 1 else ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-level", default=os.environ.get("WIRING_HARNESS_LOG_LEVEL", "INFO"))
    parser.add_argument("--log-file", default=None, help="PATH, 'default', or 'off' (auto: file on macOS/Windows only)")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the gate on loopback")
    serve.add_argument("--services", default=str(DEFAULT_SERVICES_TOML))
    serve.add_argument("--port", type=int, default=int(os.environ.get("WH_PIN_PORT", DEFAULT_PORT)))
    serve.set_defaults(func=_cmd_serve)
    status = sub.add_parser("status", help="show active lockouts")
    status.set_defaults(func=_cmd_status)
    reset = sub.add_parser("reset", help="lift lockouts")
    reset.add_argument("--site")
    reset.add_argument("--ip")
    reset.add_argument("--all", action="store_true")
    reset.set_defaults(func=_cmd_reset)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_file)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
