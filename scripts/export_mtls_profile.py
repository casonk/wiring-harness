#!/usr/bin/env python3
"""Generate a per-device iPhone-installable mTLS identity profile.

Issues a per-device client cert signed by the wiring-harness CA, bundles it
into a PKCS#12, and stages a .mobileconfig + .p12 to the snowbridge share for
easy pickup.

Usage:
    sudo python3 scripts/export_mtls_profile.py --device-name iphone
    sudo python3 scripts/export_mtls_profile.py --device-name tablet --rotate
"""

from __future__ import annotations

import argparse
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
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

DEFAULT_SHARE_TMP = Path("/srv/snowbridge/share/tmp")
DEFAULT_OWNER = "snowbridge"
DEFAULT_GROUP = "snowbridge"
DEFAULT_DEVICE_NAME = "iphone"
DEFAULT_PROFILE_IDENTIFIER_PREFIX = "local.wiring-harness.mtls"
DEFAULT_ORGANIZATION = "wiring-harness"
SLUG_PREFIX = "wiring-harness-mtls"


def _invoking_user_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        with _suppress_key_error():
            return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _suppress_key_error():
    import contextlib
    return contextlib.suppress(KeyError)


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
class IdentityPaths:
    slug: str
    cert_path: Path
    key_path: Path
    p12_path: Path
    passphrase_path: Path
    serial_path: Path
    staged_profile_path: Path
    staged_p12_path: Path


def log(message: str) -> None:
    print(message)


def fail(message: str) -> NoReturn:
    raise SetupError(message)


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        fail("run as root so issued identity and staged mobileconfig can be written safely")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a per-device iPhone-installable mTLS client identity profile.",
    )
    parser.add_argument("--device-name", default=DEFAULT_DEVICE_NAME,
                        help=f"Device label used in filenames and cert subject. Default: {DEFAULT_DEVICE_NAME}")
    parser.add_argument("--ca-cert", default=None,
                        help="Path to CA certificate. Default: ~/.config/wiring-harness/certs/ca.crt")
    parser.add_argument("--ca-key", default=None,
                        help="Path to CA private key. Default: ~/.config/wiring-harness/certs/ca.key")
    parser.add_argument("--issued-dir", default=None,
                        help="Directory to store issued client identity artifacts. "
                             "Default: ~/.config/wiring-harness/certs/issued")
    parser.add_argument("--output",
                        help="Output .mobileconfig path. "
                             f"Default: {DEFAULT_SHARE_TMP}/{SLUG_PREFIX}-<device>.mobileconfig")
    parser.add_argument("--p12-output",
                        help=f"Staged .p12 copy path. Default: {DEFAULT_SHARE_TMP}/{SLUG_PREFIX}-<device>.p12")
    parser.add_argument("--owner", default=DEFAULT_OWNER,
                        help=f"Owner for staged files. Default: {DEFAULT_OWNER}")
    parser.add_argument("--group", default=DEFAULT_GROUP,
                        help=f"Group for staged files. Default: {DEFAULT_GROUP}")
    parser.add_argument("--organization", default=DEFAULT_ORGANIZATION,
                        help=f"Organization string shown on iPhone. Default: {DEFAULT_ORGANIZATION}")
    parser.add_argument("--profile-identifier-prefix", default=DEFAULT_PROFILE_IDENTIFIER_PREFIX,
                        help=f"Profile identifier prefix. Default: {DEFAULT_PROFILE_IDENTIFIER_PREFIX}")
    parser.add_argument("--profile-name",
                        help="Human-readable profile name shown on iPhone.")
    parser.add_argument("--identity-passphrase",
                        help="Passphrase for PKCS#12 identity. Default: auto-generated.")
    parser.add_argument("--rotate", action="store_true",
                        help="Replace any existing identity for this device with a fresh one.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without changing the host.")
    return parser.parse_args()


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


def run_command(command: list[str], *, env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        fail(f"command failed: {' '.join(command)}: {detail}")


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
        fail(
            f"incomplete identity state under {identity.cert_path.parent}. "
            "Re-run with --rotate or repair manually."
        )
    if all([has_cert, has_key, has_p12]) and has_pass and not rotate:
        return

    ensure_openssl()
    ensure_directory(identity.cert_path.parent, 0o750, dry_run=dry_run)

    if dry_run:
        log(f"would issue a fresh mTLS client identity for {device_name}")
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
    finally:
        csr_path.unlink(missing_ok=True)
        ext_path.unlink(missing_ok=True)

    log(f"issued mTLS client identity for {device_name}")


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
) -> bytes:
    digest = hashlib.sha256(ca_cert_der + p12_bytes).hexdigest()
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": profile_identifier,
        "PayloadUUID": stable_uuid("wiring-harness-mtls-profile", digest),
        "PayloadDisplayName": profile_name,
        "PayloadDescription": f"Trust profile and client identity for mTLS access on {device_name}.",
        "PayloadOrganization": organization,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [
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
        ],
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)


def main() -> int:
    args = parse_args()
    device_name = args.device_name.strip()
    slug = slugify(device_name)
    profile_name = args.profile_name or f"Wiring Harness mTLS ({device_name})"
    profile_identifier = f"{args.profile_identifier_prefix}.{slug}"

    ca_cert = Path(args.ca_cert).expanduser().resolve() if args.ca_cert else _default_ca_cert()
    ca_key = Path(args.ca_key).expanduser().resolve() if args.ca_key else _default_ca_key()
    issued_dir = Path(args.issued_dir).expanduser().resolve() if args.issued_dir else _default_issued_dir()
    identity = build_identity_paths(device_name, issued_dir, args.output, args.p12_output)
    ownership = resolve_ownership(args.owner, args.group)

    try:
        if not args.dry_run:
            require_root()
        if not ca_cert.is_file():
            fail(f"CA certificate not found: {ca_cert}. Run scripts/setup-mtls.sh first.")
        if not ca_key.is_file():
            fail(f"CA private key not found: {ca_key}. Run scripts/setup-mtls.sh first.")

        passphrase = load_or_create_passphrase(
            identity.passphrase_path, args.identity_passphrase, args.rotate, args.dry_run
        )
        ensure_client_identity(
            ca_cert=ca_cert, ca_key=ca_key, identity=identity,
            device_name=device_name, passphrase=passphrase,
            rotate=args.rotate, dry_run=args.dry_run,
        )

        if args.dry_run:
            log(f"would stage {identity.staged_profile_path}")
            log(f"would stage {identity.staged_p12_path}")
            log(f"identity import password: {passphrase}")
            return 0

        ca_cert_der = load_certificate_der(ca_cert)
        p12_bytes = identity.p12_path.read_bytes()
        mobileconfig = build_mobileconfig(
            ca_cert_der=ca_cert_der, p12_bytes=p12_bytes,
            profile_identifier=profile_identifier, profile_name=profile_name,
            organization=args.organization, device_name=device_name,
            p12_file_name=identity.p12_path.name, ca_cert_file_name=ca_cert.name,
        )

        write_file(identity.staged_profile_path, mobileconfig, 0o644, ownership, args.dry_run)
        copy_file(identity.p12_path, identity.staged_p12_path, 0o640, ownership, args.dry_run)

        log(f"staged {identity.staged_profile_path}")
        log(f"staged {identity.staged_p12_path}")
        log(f"identity import password: {passphrase}")
        log("next steps on iPhone:")
        log(f"  1. Open {identity.staged_profile_path.name} from the snowbridge SMB share.")
        log("  2. Settings → Profile Downloaded → Install.")
        log("  3. Settings → General → About → Certificate Trust Settings → enable Wiring Harness CA.")
        return 0

    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
