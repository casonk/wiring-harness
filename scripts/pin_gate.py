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
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

from site_registry import DEFAULT_SERVICES_TOML, load_sites

LOG = logging.getLogger("wiring-harness.pin-gate")

DEFAULT_PORT = 8768
DEFAULT_TTL_HOURS = 12.0
COOKIE_NAME = "__Host-pin"
PIN_RE = re.compile(r"\d{4}\Z")
SITE_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
UNLOCK_PATH = "/_pin/unlock"
VERIFY_PATH = "/_pin/verify"
MAX_BODY = 1024
SECRET_CACHE_SECONDS = 600
SIGNING_KEY_ENTRY = "portfolio/pin-signing-key"
DEFAULT_VAULT = "master"
CHANNELS = ("signal", "telegram", "gmail")
SERVICE_SCRIPTS = {
    "signal": "services/signal-cli/send_message.py",
    "telegram": "services/telegram/send_message.py",
    "gmail": "services/gmail-imap/send_email.py",
}


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


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
    """A secret could not be read; the gate fails closed."""


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
            raise SecretError(f"auto-pass unavailable: {exc}") from exc
        value = result.stdout.strip("\r\n")
        if result.returncode != 0 or not value:
            raise SecretError(f"auto-pass could not provide {entry!r}")
        with self._lock:
            self._cache[entry] = (self.clock(), value)
        return value

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

    def _send_all(self, event: Newly) -> None:
        minutes = max(1, round(event.seconds / 60))
        subject = f"wiring-harness: PIN lockout ({event.kind})"
        body = f"Too many wrong PINs for {event.kind} {event.key}; locked for {minutes} min."
        for channel, (target, config) in self.targets.items():
            try:
                self._send(channel, target, config, subject, body)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                LOG.warning("lockout notification via %s failed: %s", channel, exc)

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


def safe_next(value: str | None) -> str:
    """Only a same-site absolute path may be redirected to after unlocking."""
    if not value or not value.startswith("/") or value.startswith("//") or value.startswith(UNLOCK_PATH):
        return "/"
    if any(ch in value for ch in "\\\r\n") or any(ord(ch) < 32 for ch in value):
        return "/"
    return value


def client_ip(headers) -> str:
    # Caddy replaces X-Forwarded-For for untrusted clients and this service binds loopback only,
    # so the last hop is the address Caddy actually saw.
    forwarded = headers.get("X-Forwarded-For", "")
    last = forwarded.split(",")[-1].strip()
    return last or "unknown"


class Gate:
    def __init__(
        self,
        sites: dict[str, SiteConfig],
        secrets: AutoPassSecrets,
        lockouts: Lockouts,
        notifier: Notifier,
        signing_key_entry: str = SIGNING_KEY_ENTRY,
        clock=time.time,
    ) -> None:
        self.sites = sites
        self.secrets = secrets
        self.lockouts = lockouts
        self.notifier = notifier
        self.signing_key_entry = signing_key_entry
        self.clock = clock

    def has_valid_cookie(self, site: SiteConfig, cookie_header: str) -> bool:
        value = _cookie(cookie_header, COOKIE_NAME)
        if not value:
            return False
        pin = self.secrets.get(site.entry)
        key = self.secrets.get(self.signing_key_entry)
        return cookie_valid(value, key, site.name, pin, self.clock())

    def attempt(self, site: SiteConfig, ip: str, guess: str) -> tuple[str, int, str | None]:
        """Returns (outcome, lock_seconds, cookie). Outcome: ok, wrong, or locked."""
        remaining = self.lockouts.locked_for(site.name, ip)
        if remaining:
            LOG.info("refused attempt on %s from %s: locked for %ss", site.name, ip, remaining)
            return "locked", remaining, None
        pin = self.secrets.get(site.entry)
        key = self.secrets.get(self.signing_key_entry)
        if PIN_RE.match(guess or "") and hmac.compare_digest(guess.encode(), pin.encode()):
            self.lockouts.record_success(site.name)
            expires = int(self.clock()) + site.ttl_seconds
            LOG.info("unlocked %s for %s", site.name, ip)
            return "ok", 0, make_cookie_value(key, site.name, pin, expires)
        for event in self.lockouts.record_failure(site.name, ip):
            LOG.warning(
                "lockout: %s %s for %ss (attempt on %s from %s)", event.kind, event.key, event.seconds, site.name, ip
            )
            self.notifier.notify(event)
        LOG.info("wrong PIN on %s from %s", site.name, ip)
        return "wrong", self.lockouts.locked_for(site.name, ip), None


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
</form></body></html>
"""


def render_page(next_path: str, message: str = "", error: bool = False) -> bytes:
    note = f'<p class="{"err" if error else ""}">{html.escape(message)}</p>' if message else ""
    return PAGE.format(action=UNLOCK_PATH, next=html.escape(next_path, quote=True), message=note).encode()


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
            self._send(HTTPStatus.NOT_FOUND, b"not found")

        do_HEAD = do_GET  # noqa: N815

        def _verify(self, site: SiteConfig) -> None:
            try:
                valid = gate.has_valid_cookie(site, self.headers.get("Cookie", ""))
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, b"locked: secrets unavailable")
            if valid:
                return self._send(HTTPStatus.NO_CONTENT)
            original = self.headers.get("X-Forwarded-Uri", "/")
            if self.headers.get("X-Forwarded-Method", "GET") in {"GET", "HEAD"}:
                return self._redirect_to_unlock(safe_next(original))
            self._send(HTTPStatus.UNAUTHORIZED, b"PIN required")

        def do_POST(self):  # noqa: N802
            path = self.path.partition("?")[0]
            site = self._site()
            if site is None:
                return
            if path != UNLOCK_PATH:
                return self._send(HTTPStatus.NOT_FOUND, b"not found")
            origin = self.headers.get("Origin")
            host = self.headers.get("Host", "")
            if self.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and origin.split("://", 1)[-1] != host):
                LOG.warning("cross-origin unlock attempt on %s refused", site.name)
                return self._send(HTTPStatus.FORBIDDEN, b"cross-origin request refused")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"too large")
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            guess = form.get("pin", [""])[0]
            next_path = safe_next(form.get("next", [""])[0])
            try:
                outcome, seconds, cookie = gate.attempt(site, client_ip(self.headers), guess)
            except SecretError as exc:
                LOG.error("failing closed for %s: %s", site.name, exc)
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, b"locked: secrets unavailable")
            if outcome == "ok":
                attrs = f"{COOKIE_NAME}={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={site.ttl_seconds}"
                return self._send(HTTPStatus.SEE_OTHER, headers={"Location": next_path, "Set-Cookie": attrs})
            if outcome == "locked" or seconds:
                return self._send(HTTPStatus.TOO_MANY_REQUESTS, render_page(next_path, lock_message(seconds), True))
            self._send(HTTPStatus.UNAUTHORIZED, render_page(next_path, "Incorrect PIN.", True))

    return Handler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_serve(args: argparse.Namespace) -> int:
    sites = sites_from_registry(Path(args.services))
    if not sites:
        LOG.error("no sites with pin = true in %s", args.services)
        return 1
    gate = Gate(
        sites,
        AutoPassSecrets(vault=os.environ.get("WH_PIN_VAULT", DEFAULT_VAULT)),
        Lockouts(StateStore(default_state_file()), Policy.from_env()),
        Notifier.from_env(),
        signing_key_entry=os.environ.get("WH_PIN_SIGNING_KEY_ENTRY", SIGNING_KEY_ENTRY),
    )
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
    configure_logging(args.log_level)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
