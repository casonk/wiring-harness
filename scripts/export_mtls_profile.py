#!/usr/bin/env python3
"""Generate per-device mTLS identity profiles for all registered devices.

Issues a per-device client cert signed by the wiring-harness CA for each entry
in devices.toml, then delivers it according to device type:

  desktop  — installs CA trust and per-device identity into Firefox and Chromium
             NSS databases on this machine
  mobile   — stages a .mobileconfig + .p12 to /srv/snowbridge/share/tmp/ for
             pickup via the snowbridge SMB share

Usage:
    sudo python3 scripts/export_mtls_profile.py --all-devices
    sudo python3 scripts/export_mtls_profile.py --device-name iphone-14-pro
    sudo python3 scripts/export_mtls_profile.py --device-name iphone-14-pro --rotate
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import hashlib
import os
import plistlib
import pwd
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib  # type: ignore[no-redef]
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

DEFAULT_DEVICES_TOML = REPO_ROOT / "devices.toml"
DEFAULT_SHARE_TMP = Path("/srv/snowbridge/share/tmp")
DEFAULT_OWNER = "snowbridge"
DEFAULT_GROUP = "snowbridge"
DEFAULT_PROFILE_IDENTIFIER_PREFIX = "local.wiring-harness.mtls"
DEFAULT_ORGANIZATION = "wiring-harness"
SLUG_PREFIX = "wiring-harness-mtls"

SNOWBRIDGE_CA_CERT = Path("/var/lib/snowbridge/caddy/data/mtls/client-ca.crt")
SNOWBRIDGE_CA_KEY = Path("/var/lib/snowbridge/caddy/data/mtls/client-ca.key")
SNOWBRIDGE_ISSUED_DIR = Path("/var/lib/snowbridge/caddy/data/mtls/issued")
SNOWBRIDGE_SLUG_PREFIX = "snowbridge-caddy-mtls"

CA_NICK = "Wiring Harness CA"
LEGACY_NSS_NICKS = (
    "Clockwork CA",
    "clockwork-client",
    "clockwork-client - Portfolio",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _invoking_user_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        with contextlib.suppress(KeyError):
            return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _default_ca_cert() -> Path:
    return _invoking_user_home() / ".config" / "wiring-harness" / "certs" / "ca.crt"


def _default_ca_key() -> Path:
    return _invoking_user_home() / ".config" / "wiring-harness" / "certs" / "ca.key"


def _default_issued_dir() -> Path:
    return _invoking_user_home() / ".config" / "wiring-harness" / "certs" / "issued"


class SetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Ownership:
    uid: int
    gid: int
    owner_name: str
    group_name: str


@dataclass(frozen=True)
class ExtraP12:
    p12_bytes: bytes
    p12_file_name: str
    display_name: str
    identity_slug: str
    passphrase: str


@dataclass(frozen=True)
class IdentityPaths:
    slug: str
    cert_path: Path
    key_path: Path
    p12_path: Path
    passphrase_path: Path
    serial_path: Path
    staged_profile_path: Path
    staged_p12_path: Path


@dataclass(frozen=True)
class DeviceSpec:
    name: str
    type: str    # "desktop" | "mobile"
    platform: str  # "linux" | "ios" | "macos" | …


def log(message: str) -> None:
    print(message)


def fail(message: str) -> NoReturn:
    raise SetupError(message)


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        fail("run as root so issued identity and staged files can be written safely")


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not slug:
        fail("device name must contain at least one alphanumeric character")
    return slug


def resolve_ownership(owner_name: str, group_name: str) -> Ownership:
    try:
        owner = pwd.getpwnam(owner_name)
    except KeyError:
        fail(f"owner account not found: {owner_name}")
    try:
        group = grp.getgrnam(group_name)
    except KeyError:
        fail(f"group not found: {group_name}")
    return Ownership(uid=owner.pw_uid, gid=group.gr_gid, owner_name=owner_name, group_name=group_name)


def ensure_openssl() -> None:
    if not shutil.which("openssl"):
        fail("openssl is not installed")


def ensure_directory(path: Path, mode: int, ownership: Ownership | None = None, dry_run: bool = False) -> None:
    if dry_run:
        extra = f" owner={ownership.owner_name}:{ownership.group_name}" if ownership else ""
        log(f"would ensure directory {path} mode={mode:o}{extra}")
        return
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    if ownership is not None:
        os.chown(path, ownership.uid, ownership.gid)


def write_file(path: Path, content: bytes, mode: int, ownership: Ownership | None, dry_run: bool) -> None:
    ensure_directory(path.parent, 0o2770 if ownership else 0o750, ownership, dry_run)
    if dry_run:
        log(f"would write {path} mode={mode:o}")
        return
    path.write_bytes(content)
    os.chmod(path, mode)
    if ownership is not None:
        os.chown(path, ownership.uid, ownership.gid)


def copy_file(source: Path, target: Path, mode: int, ownership: Ownership, dry_run: bool) -> None:
    ensure_directory(target.parent, 0o2770, ownership, dry_run)
    if dry_run:
        log(f"would copy {source} -> {target} mode={mode:o}")
        return
    shutil.copy2(source, target)
    os.chmod(target, mode)
    os.chown(target, ownership.uid, ownership.gid)


def load_certificate_der(cert_path: Path) -> bytes:
    if not cert_path.is_file():
        fail(f"certificate not found: {cert_path}")
    raw = cert_path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" not in raw:
        return raw
    try:
        pem_text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"certificate is PEM-encoded but not ASCII-readable: {cert_path}")
    try:
        der_bytes = ssl.PEM_cert_to_DER_cert(pem_text)
    except ValueError as exc:
        fail(f"unable to parse PEM certificate at {cert_path}: {exc}")
    return der_bytes if isinstance(der_bytes, bytes) else der_bytes.encode("latin1")


def stable_uuid(label: str, digest: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{label}:{digest}")).upper()


def run_command(command: list[str], *, env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        fail(f"command failed: {' '.join(command)}: {detail}")


# ---------------------------------------------------------------------------
# Device registry
# ---------------------------------------------------------------------------


def load_devices(path: Path) -> list[DeviceSpec]:
    """Load devices.toml and merge devices.local.toml entries if present.

    The local file is resolved as <stem>.local.toml alongside the main file
    (e.g. devices.local.toml next to devices.toml).  Entries are matched by
    ``name``; unknown names are appended as new devices.
    """
    data = tomllib.loads(path.read_text())
    local_path = path.with_name(path.stem + ".local.toml")
    if local_path.exists():
        local = tomllib.loads(local_path.read_text())
        local_by_name = {e["name"]: e for e in local.get("devices", [])}
        base_by_name = {e["name"]: e for e in data.get("devices", [])}
        for name, overrides in local_by_name.items():
            if name in base_by_name:
                base_by_name[name].update(overrides)
            else:
                data.setdefault("devices", []).append(overrides)

    devices = []
    for entry in data.get("devices", []):
        devices.append(DeviceSpec(
            name=entry["name"],
            type=entry.get("type", "mobile"),
            platform=entry.get("platform", "ios"),
        ))
    return devices


# ---------------------------------------------------------------------------
# Identity issuance
# ---------------------------------------------------------------------------


def build_identity_paths(
    device_name: str, issued_dir: Path, output: str | None, p12_output: str | None
) -> IdentityPaths:
    slug = slugify(device_name)
    staged_profile = (
        Path(output).expanduser().resolve()
        if output
        else DEFAULT_SHARE_TMP / f"{SLUG_PREFIX}-{slug}.mobileconfig"
    )
    staged_p12 = (
        Path(p12_output).expanduser().resolve()
        if p12_output
        else DEFAULT_SHARE_TMP / f"{SLUG_PREFIX}-{slug}.p12"
    )
    prefix = issued_dir / f"{SLUG_PREFIX}-{slug}"
    return IdentityPaths(
        slug=slug,
        cert_path=prefix.with_suffix(".crt"),
        key_path=prefix.with_suffix(".key"),
        p12_path=prefix.with_suffix(".p12"),
        passphrase_path=prefix.with_suffix(".passphrase"),
        serial_path=issued_dir / "ca.srl",
        staged_profile_path=staged_profile,
        staged_p12_path=staged_p12,
    )


def load_or_create_passphrase(
    passphrase_path: Path, explicit: str | None, rotate: bool, dry_run: bool
) -> str:
    if explicit is not None:
        if not explicit:
            fail("identity passphrase cannot be empty")
        if not dry_run:
            ensure_directory(passphrase_path.parent, 0o750)
            passphrase_path.write_text(explicit + "\n", encoding="utf-8")
            os.chmod(passphrase_path, 0o600)
        return explicit
    if passphrase_path.exists() and not rotate:
        passphrase = passphrase_path.read_text(encoding="utf-8").strip()
        if not passphrase:
            fail(f"stored passphrase file is empty: {passphrase_path}")
        return passphrase
    passphrase = secrets.token_urlsafe(24)
    if not dry_run:
        ensure_directory(passphrase_path.parent, 0o750)
        passphrase_path.write_text(passphrase + "\n", encoding="utf-8")
        os.chmod(passphrase_path, 0o600)
    return passphrase


def ensure_client_identity(
    *,
    ca_cert: Path,
    ca_key: Path,
    identity: IdentityPaths,
    device_name: str,
    passphrase: str,
    rotate: bool,
    dry_run: bool,
) -> None:
    has_cert = identity.cert_path.exists()
    has_key = identity.key_path.exists()
    has_p12 = identity.p12_path.exists()
    has_pass = identity.passphrase_path.exists()

    if any([has_cert, has_key, has_p12]) and (not all([has_cert, has_key, has_p12]) or not has_pass) and not rotate:
        fail(f"incomplete identity state under {identity.cert_path.parent}. Re-run with --rotate or repair manually.")
    if all([has_cert, has_key, has_p12]) and has_pass and not rotate:
        return

    ensure_openssl()
    ensure_directory(identity.cert_path.parent, 0o750, dry_run=dry_run)

    if dry_run:
        log(f"  would issue a fresh mTLS client identity for {device_name}")
        return

    for path in (identity.cert_path, identity.key_path, identity.p12_path):
        path.unlink(missing_ok=True)

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf") as fh:
        fh.write(
            "[v3_client]\n"
            "basicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = clientAuth\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n"
        )
        ext_path = Path(fh.name)

    csr_path = identity.cert_path.with_suffix(".csr")
    env = {**os.environ, "WH_P12_PASS": passphrase}

    try:
        run_command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(identity.key_path), "-out", str(csr_path),
                     "-subj", f"/CN=Wiring Harness {device_name} Client/O=Portfolio/OU=Admin"])
        run_command(["openssl", "x509", "-req",
                     "-in", str(csr_path), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                     "-CAserial", str(identity.serial_path), "-CAcreateserial",
                     "-out", str(identity.cert_path), "-days", "825", "-sha256",
                     "-extfile", str(ext_path), "-extensions", "v3_client"])
        run_command(["openssl", "pkcs12", "-export",
                     "-name", f"Wiring Harness {device_name} Client",
                     "-inkey", str(identity.key_path), "-in", str(identity.cert_path),
                     "-certfile", str(ca_cert), "-out", str(identity.p12_path),
                     "-passout", "env:WH_P12_PASS"], env=env)
        os.chmod(identity.key_path, 0o600)
        os.chmod(identity.cert_path, 0o644)
        os.chmod(identity.p12_path, 0o600)
        _chown_to_invoking_user([
            identity.cert_path, identity.key_path,
            identity.p12_path, identity.passphrase_path,
            identity.cert_path.parent,
        ])
    finally:
        csr_path.unlink(missing_ok=True)
        ext_path.unlink(missing_ok=True)

    log(f"  issued mTLS client identity for {device_name}")


# ---------------------------------------------------------------------------
# Desktop delivery — NSS browser install
# ---------------------------------------------------------------------------


def _find_nss_databases(home: Path) -> list[Path]:
    """Return NSS database directories for Firefox, Chromium, and Google Chrome.

    The shared ~/.pki/nssdb is used by both Chromium and Google Chrome on Linux.
    It is created here if absent so certutil can populate it before the browser
    has been launched for the first time.
    """
    dbs: list[Path] = []

    ff_roots = [
        home / ".mozilla" / "firefox",
        home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
    ]
    for ff_root in ff_roots:
        if not ff_root.is_dir():
            continue
        for child in ff_root.iterdir():
            if child.is_dir() and (child.suffix in (".default", ".default-release", ".default-esr")
                                    or child.name.endswith((".default", ".default-release", ".default-esr"))):
                dbs.append(child)

    # Shared NSS store used by both Chromium and Google Chrome on Linux.
    # Create it if missing so certutil can initialise it before first browser launch.
    chromium_db = home / ".pki" / "nssdb"
    if not chromium_db.is_dir() and shutil.which("certutil"):
        chromium_db.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["certutil", "-N", "-d", f"sql:{chromium_db}", "--empty-password"],
            capture_output=True,
        )
    if chromium_db.is_dir():
        dbs.append(chromium_db)

    return dbs


def _nss_remove_nick(db: str, nick: str) -> None:
    """Remove all entries matching nick from an NSS database (handles duplicates)."""
    for _ in range(10):
        r = subprocess.run(["certutil", "-D", "-d", db, "-n", nick],
                           capture_output=True, text=True)
        if r.returncode != 0:
            break


def _chown_to_invoking_user(paths: list[Path]) -> None:
    """Return ownership of issued files to the original (non-root) user after sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return
    try:
        pw = pwd.getpwnam(sudo_user)
        for path in paths:
            if path.exists():
                os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError):
        pass


def _restart_browsers(user: str | None) -> None:
    """Kill browsers (flushes NSS cache and socket pool) then relaunch Chromium as the user."""
    # Use -f (full command line) not -x (comm field) — comm is capped at 15 chars on Linux
    # so names like "chromium-browser" (16 chars) would silently not match with -x.
    browsers = ["chromium-browser", "chromium", "google-chrome", "firefox"]
    killed: list[str] = []
    for b in browsers:
        r = subprocess.run(["pkill", "-f", b], capture_output=True)
        if r.returncode == 0:
            killed.append(b)
    if killed:
        log(f"  [browser] killed: {', '.join(killed)}")
        time.sleep(2)

    if not user:
        log("  [browser] SUDO_USER not set — restart browser manually to pick up cert changes")
        return

    chromium = shutil.which("chromium-browser") or shutil.which("chromium") or shutil.which("google-chrome")
    if not chromium:
        log("  [browser] chromium not found — restart browser manually")
        return

    try:
        uid = pwd.getpwnam(user).pw_uid
        wayland = os.environ.get("WAYLAND_DISPLAY", "wayland-0")
        subprocess.Popen(
            [
                "sudo", "-u", user, "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"WAYLAND_DISPLAY={wayland}",
                f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
                chromium,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log(f"  [browser] relaunched {chromium} as {user}")
    except Exception as exc:
        log(f"  [browser] relaunch failed ({exc}) — start {chromium} manually")


def install_to_nss(
    *, ca_cert: Path, p12_path: Path, passphrase: str, device_name: str, home: Path, dry_run: bool
) -> None:
    """Install the CA trust and per-device identity into Firefox and Chromium NSS databases."""
    if not shutil.which("certutil"):
        log("  [NSS] certutil not found — install nss-tools (dnf install nss-tools)")
        return
    if not shutil.which("pk12util"):
        log("  [NSS] pk12util not found — install nss-tools")
        return

    databases = _find_nss_databases(home)
    if not databases:
        log("  [NSS] no Firefox or Chromium NSS databases found")
        return

    identity_nick = f"Wiring Harness {device_name} Client"

    for db_path in databases:
        label = db_path.name
        db = f"sql:{db_path}"

        if dry_run:
            log(f"  [NSS] would update {db_path}")
            continue

        # Pre-remove stale entries to avoid duplicate accumulation. Also purge
        # legacy clockwork nicknames left behind before shared-Caddy migration.
        for nick in [CA_NICK, identity_nick, f"{identity_nick} - Portfolio", *LEGACY_NSS_NICKS]:
            _nss_remove_nick(db, nick)

        # CA trust
        r = subprocess.run(["certutil", "-A", "-d", db, "-n", CA_NICK, "-t", "CT,,", "-i", str(ca_cert)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            log(f"  [NSS] CA trust added: {label}")
        else:
            log(f"  [NSS] CA trust failed ({label}): {r.stderr.strip()}")

        # Per-device client identity
        r = subprocess.run(["pk12util", "-i", str(p12_path), "-d", db, "-W", passphrase],
                           capture_output=True, text=True)
        if r.returncode == 0:
            log(f"  [NSS] client identity added: {label}")
        else:
            log(f"  [NSS] client identity failed ({label}): {r.stderr.strip()}")


# ---------------------------------------------------------------------------
# Mobile delivery — mobileconfig staging
# ---------------------------------------------------------------------------


def build_mobileconfig(
    *,
    ca_cert_der: bytes,
    p12_bytes: bytes,
    profile_identifier: str,
    profile_name: str,
    organization: str,
    device_name: str,
    p12_file_name: str,
    ca_cert_file_name: str,
    extra_p12s: list[ExtraP12] | None = None,
) -> bytes:
    all_p12_bytes = p12_bytes + b"".join(e.p12_bytes for e in (extra_p12s or []))
    digest = hashlib.sha256(ca_cert_der + all_p12_bytes).hexdigest()
    payload_content: list[dict] = [
        {
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{profile_identifier}.root",
            "PayloadUUID": stable_uuid("wiring-harness-mtls-root", digest),
            "PayloadDisplayName": "Wiring Harness CA",
            "PayloadDescription": "Installs the Wiring Harness CA so the device trusts all private HTTPS endpoints.",  # noqa: E501
            "PayloadCertificateFileName": ca_cert_file_name,
            "PayloadContent": ca_cert_der,
        },
        {
            "PayloadType": "com.apple.security.pkcs12",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{profile_identifier}.identity",
            "PayloadUUID": stable_uuid("wiring-harness-mtls-identity", digest),
            "PayloadDisplayName": f"Wiring Harness mTLS Client Identity ({device_name})",
            "PayloadDescription": "Installs the client certificate for private mTLS access.",
            "PayloadCertificateFileName": p12_file_name,
            "PayloadContent": p12_bytes,
        },
    ]
    for extra in (extra_p12s or []):
        payload_content.append({
            "PayloadType": "com.apple.security.pkcs12",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{profile_identifier}.{extra.identity_slug}",
            "PayloadUUID": stable_uuid(f"wiring-harness-extra-{extra.identity_slug}", digest),
            "PayloadDisplayName": extra.display_name,
            "PayloadDescription": f"Installs the client certificate for {extra.display_name}.",
            "PayloadCertificateFileName": extra.p12_file_name,
            "PayloadContent": extra.p12_bytes,
        })
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": profile_identifier,
        "PayloadUUID": stable_uuid("wiring-harness-mtls-profile", digest),
        "PayloadDisplayName": profile_name,
        "PayloadDescription": f"Trust profile and client identity for mTLS access on {device_name}.",
        "PayloadOrganization": organization,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payload_content,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)


def stage_mobile_profile(
    *,
    ca_cert: Path,
    identity: IdentityPaths,
    device_name: str,
    profile_identifier: str,
    profile_name: str,
    organization: str,
    ownership: Ownership,
    dry_run: bool,
    extra_p12s: list[ExtraP12] | None = None,
) -> None:
    ca_cert_der = load_certificate_der(ca_cert)
    p12_bytes = identity.p12_path.read_bytes()
    mobileconfig = build_mobileconfig(
        ca_cert_der=ca_cert_der, p12_bytes=p12_bytes,
        profile_identifier=profile_identifier, profile_name=profile_name,
        organization=organization, device_name=device_name,
        p12_file_name=identity.p12_path.name, ca_cert_file_name=ca_cert.name,
        extra_p12s=extra_p12s,
    )
    write_file(identity.staged_profile_path, mobileconfig, 0o644, ownership, dry_run)
    copy_file(identity.p12_path, identity.staged_p12_path, 0o640, ownership, dry_run)
    log(f"  staged {identity.staged_profile_path.name}")
    log(f"  staged {identity.staged_p12_path.name}")
    log(f"  wiring-harness identity import password: {identity.passphrase_path.read_text().strip()}")
    for extra in (extra_p12s or []):
        log(f"  {extra.display_name} import password: {extra.passphrase}")
    log("  install steps on iPhone:")
    log(f"    1. Open {identity.staged_profile_path.name} from the snowbridge SMB share.")
    log("    2. Settings → Profile Downloaded → Install.")
    log("    3. Settings → General → About → Certificate Trust Settings → enable Wiring Harness CA.")


# ---------------------------------------------------------------------------
# Snowbridge extra identity
# ---------------------------------------------------------------------------


def _gather_snowbridge_extra_p12(
    *,
    device_name: str,
    slug: str,
    ca_cert: Path,
    ca_key: Path,
    issued_dir: Path,
    rotate: bool,
    dry_run: bool,
) -> ExtraP12 | None:
    """Issue (if needed) and load the snowbridge filebrowser client identity."""
    if not ca_cert.is_file():
        return None

    prefix = issued_dir / f"{SNOWBRIDGE_SLUG_PREFIX}-{slug}"
    cert_path = prefix.with_suffix(".crt")
    key_path = prefix.with_suffix(".key")
    p12_path = prefix.with_suffix(".p12")
    passphrase_path = prefix.with_suffix(".passphrase")
    serial_path = issued_dir / "client-ca.srl"

    needs_issue = not (
        all([cert_path.exists(), key_path.exists(), p12_path.exists()])
        and passphrase_path.exists()
    ) or rotate

    if needs_issue:
        if not ca_key.is_file():
            log(f"  [snowbridge] CA key not found — skipping snowbridge identity for {device_name}")
            return None

        ensure_openssl()
        if dry_run:
            log(f"  [snowbridge] would issue identity for {device_name}")
            return None

        if passphrase_path.exists() and not rotate:
            passphrase = passphrase_path.read_text(encoding="utf-8").strip()
        else:
            passphrase = secrets.token_urlsafe(24)

        ensure_directory(issued_dir, 0o750, dry_run=False)
        passphrase_path.write_text(passphrase + "\n", encoding="utf-8")
        os.chmod(passphrase_path, 0o600)

        for path in (cert_path, key_path, p12_path):
            path.unlink(missing_ok=True)

        csr_path = cert_path.with_suffix(".csr")
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf") as fh:
            fh.write(
                "[v3_client]\n"
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = clientAuth\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
            )
            ext_path = Path(fh.name)

        env = {**os.environ, "SB_P12_PASS": passphrase}
        try:
            run_command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", str(key_path), "-out", str(csr_path),
                         "-subj", f"/CN=Snowbridge {device_name} Client/O=snowbridge"])
            run_command(["openssl", "x509", "-req",
                         "-in", str(csr_path), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                         "-CAserial", str(serial_path), "-CAcreateserial",
                         "-out", str(cert_path), "-days", "825", "-sha256",
                         "-extfile", str(ext_path), "-extensions", "v3_client"])
            run_command(["openssl", "pkcs12", "-export",
                         "-name", f"Snowbridge {device_name} Client",
                         "-inkey", str(key_path), "-in", str(cert_path),
                         "-certfile", str(ca_cert), "-out", str(p12_path),
                         "-passout", "env:SB_P12_PASS"], env=env)
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            os.chmod(p12_path, 0o600)
            _chown_to_invoking_user([cert_path, key_path, p12_path, passphrase_path, issued_dir])
        finally:
            csr_path.unlink(missing_ok=True)
            ext_path.unlink(missing_ok=True)

        log(f"  [snowbridge] issued identity for {device_name}")

    if not p12_path.is_file():
        return None

    try:
        passphrase = passphrase_path.read_text(encoding="utf-8").strip()
    except PermissionError:
        log(f"  [snowbridge] cannot read passphrase for {device_name}: {passphrase_path}")
        return None

    return ExtraP12(
        p12_bytes=p12_path.read_bytes(),
        p12_file_name=p12_path.name,
        display_name=f"Snowbridge mTLS Client Identity ({device_name})",
        identity_slug=f"snowbridge-{slug}",
        passphrase=passphrase,
    )


# ---------------------------------------------------------------------------
# Per-device orchestration
# ---------------------------------------------------------------------------


def export_device(
    *,
    device: DeviceSpec,
    ca_cert: Path,
    ca_key: Path,
    issued_dir: Path,
    ownership: Ownership,
    profile_identifier_prefix: str,
    organization: str,
    rotate: bool,
    dry_run: bool,
    output: str | None = None,
    p12_output: str | None = None,
    passphrase_override: str | None = None,
    snowbridge_ca_cert: Path = SNOWBRIDGE_CA_CERT,
    snowbridge_ca_key: Path = SNOWBRIDGE_CA_KEY,
    snowbridge_issued_dir: Path = SNOWBRIDGE_ISSUED_DIR,
    no_snowbridge: bool = False,
) -> None:
    log(f"\n── {device.name} ({device.type}/{device.platform}) ──")
    identity = build_identity_paths(device.name, issued_dir, output, p12_output)
    passphrase = load_or_create_passphrase(
        identity.passphrase_path, passphrase_override, rotate, dry_run
    )
    ensure_client_identity(
        ca_cert=ca_cert, ca_key=ca_key, identity=identity,
        device_name=device.name, passphrase=passphrase,
        rotate=rotate, dry_run=dry_run,
    )

    if dry_run:
        log(f"  would deliver for {device.type}")
        return

    profile_identifier = f"{profile_identifier_prefix}.{identity.slug}"
    profile_name = f"Wiring Harness mTLS ({device.name})"

    if device.type == "desktop":
        install_to_nss(
            ca_cert=ca_cert, p12_path=identity.p12_path, passphrase=passphrase,
            device_name=device.name, home=_invoking_user_home(), dry_run=dry_run,
        )
    else:
        extra_p12s: list[ExtraP12] = []
        if not no_snowbridge:
            sb = _gather_snowbridge_extra_p12(
                device_name=device.name, slug=identity.slug,
                ca_cert=snowbridge_ca_cert, ca_key=snowbridge_ca_key,
                issued_dir=snowbridge_issued_dir, rotate=rotate, dry_run=dry_run,
            )
            if sb is not None:
                extra_p12s.append(sb)
        stage_mobile_profile(
            ca_cert=ca_cert, identity=identity, device_name=device.name,
            profile_identifier=profile_identifier, profile_name=profile_name,
            organization=organization, ownership=ownership, dry_run=dry_run,
            extra_p12s=extra_p12s or None,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate per-device mTLS identity profiles for all registered devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all-devices", action="store_true",
                      help="Process all devices in devices.toml")
    mode.add_argument("--device-name", metavar="NAME",
                      help="Process a single device by name (must exist in devices.toml or be given --type)")

    parser.add_argument("--devices", metavar="PATH", default=str(DEFAULT_DEVICES_TOML),
                        help=f"Path to devices.toml (default: {DEFAULT_DEVICES_TOML})")
    parser.add_argument("--type", choices=["desktop", "mobile"], default="mobile",
                        help="Device type when --device-name is used and not in devices.toml (default: mobile)")
    parser.add_argument("--platform", default="ios",
                        help="Platform when --device-name is used and not in devices.toml (default: ios)")
    parser.add_argument("--ca-cert", default=None,
                        help="Path to CA certificate. Default: ~/.config/wiring-harness/certs/ca.crt")
    parser.add_argument("--ca-key", default=None,
                        help="Path to CA private key. Default: ~/.config/wiring-harness/certs/ca.key")
    parser.add_argument("--issued-dir", default=None,
                        help="Directory for issued client identities. Default: ~/.config/wiring-harness/certs/issued")
    parser.add_argument("--output", help="Output .mobileconfig path (single device only)")
    parser.add_argument("--p12-output", help="Staged .p12 path (single device only)")
    parser.add_argument("--owner", default=DEFAULT_OWNER,
                        help=f"Owner for staged mobile files. Default: {DEFAULT_OWNER}")
    parser.add_argument("--group", default=DEFAULT_GROUP,
                        help=f"Group for staged mobile files. Default: {DEFAULT_GROUP}")
    parser.add_argument("--organization", default=DEFAULT_ORGANIZATION,
                        help=f"Organization string in profiles. Default: {DEFAULT_ORGANIZATION}")
    parser.add_argument("--profile-identifier-prefix", default=DEFAULT_PROFILE_IDENTIFIER_PREFIX,
                        help=f"Profile identifier prefix. Default: {DEFAULT_PROFILE_IDENTIFIER_PREFIX}")
    parser.add_argument("--identity-passphrase",
                        help="Passphrase for PKCS#12 identity (single device only). Default: auto-generated.")
    parser.add_argument("--rotate", action="store_true",
                        help="Replace existing identities with freshly signed ones.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without changing the host.")
    parser.add_argument("--snowbridge-ca-cert", default=None,
                        help=f"Snowbridge filebrowser client CA cert. Default: {SNOWBRIDGE_CA_CERT}")
    parser.add_argument("--snowbridge-ca-key", default=None,
                        help=f"Snowbridge filebrowser client CA key. Default: {SNOWBRIDGE_CA_KEY}")
    parser.add_argument("--snowbridge-issued-dir", default=None,
                        help=f"Directory for snowbridge-issued client identities. Default: {SNOWBRIDGE_ISSUED_DIR}")
    parser.add_argument("--no-snowbridge", action="store_true",
                        help="Skip the snowbridge filebrowser client identity payload.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    ca_cert = Path(args.ca_cert).expanduser().resolve() if args.ca_cert else _default_ca_cert()
    ca_key = Path(args.ca_key).expanduser().resolve() if args.ca_key else _default_ca_key()
    issued_dir = Path(args.issued_dir).expanduser().resolve() if args.issued_dir else _default_issued_dir()
    ownership = resolve_ownership(args.owner, args.group)
    sb_ca_cert = Path(args.snowbridge_ca_cert).expanduser().resolve() if args.snowbridge_ca_cert else SNOWBRIDGE_CA_CERT
    sb_ca_key = Path(args.snowbridge_ca_key).expanduser().resolve() if args.snowbridge_ca_key else SNOWBRIDGE_CA_KEY
    sb_issued_dir = Path(args.snowbridge_issued_dir).expanduser().resolve() if args.snowbridge_issued_dir else SNOWBRIDGE_ISSUED_DIR

    try:
        if not args.dry_run:
            require_root()
        if not ca_cert.is_file():
            fail(f"CA certificate not found: {ca_cert}. Run scripts/setup-mtls.sh first.")
        if not ca_key.is_file():
            fail(f"CA private key not found: {ca_key}. Run scripts/setup-mtls.sh first.")

        devices_path = Path(args.devices)

        has_desktop = False

        if args.all_devices:
            if not devices_path.exists():
                fail(f"devices.toml not found: {devices_path}")
            devices = load_devices(devices_path)
            if not devices:
                fail("no devices found in devices.toml")
            log(f"Processing {len(devices)} device(s) from {devices_path}")
            for device in devices:
                export_device(
                    device=device, ca_cert=ca_cert, ca_key=ca_key, issued_dir=issued_dir,
                    ownership=ownership, profile_identifier_prefix=args.profile_identifier_prefix,
                    organization=args.organization, rotate=args.rotate, dry_run=args.dry_run,
                    snowbridge_ca_cert=sb_ca_cert, snowbridge_ca_key=sb_ca_key,
                    snowbridge_issued_dir=sb_issued_dir, no_snowbridge=args.no_snowbridge,
                )
                if device.type == "desktop":
                    has_desktop = True
        else:
            # Single device: look it up in devices.toml if it exists, else use CLI args
            device = None
            if devices_path.exists():
                for d in load_devices(devices_path):
                    if d.name == args.device_name:
                        device = d
                        break
            if device is None:
                device = DeviceSpec(name=args.device_name, type=args.type, platform=args.platform)
            export_device(
                device=device, ca_cert=ca_cert, ca_key=ca_key, issued_dir=issued_dir,
                ownership=ownership, profile_identifier_prefix=args.profile_identifier_prefix,
                organization=args.organization, rotate=args.rotate, dry_run=args.dry_run,
                output=args.output, p12_output=args.p12_output,
                passphrase_override=args.identity_passphrase,
                snowbridge_ca_cert=sb_ca_cert, snowbridge_ca_key=sb_ca_key,
                snowbridge_issued_dir=sb_issued_dir, no_snowbridge=args.no_snowbridge,
            )
            if device.type == "desktop":
                has_desktop = True

        if has_desktop and not args.dry_run:
            log("\n==> Restarting browsers to pick up NSS changes...")
            _restart_browsers(os.environ.get("SUDO_USER"))

    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
