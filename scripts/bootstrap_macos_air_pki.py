#!/usr/bin/env python3
"""Bootstrap owner-only PKI material for the temporary macOS Air edge.

The bootstrap is deliberately local and inert: it creates certificate files
but never reads or changes Keychain state, starts Caddy, or invokes launchctl.
All OpenSSL calls use fixed argument vectors without a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_CERTS_DIR = Path.home() / ".config" / "wiring-harness" / "certs"
DEFAULT_OPENSSL = Path("/opt/homebrew/bin/openssl")
DEFAULT_WIREGUARD_IP = "10.99.0.254"
CA_DAYS = 3650
LEAF_DAYS = 397
OPENSSL_TIMEOUT_SECONDS = 45
CERTIFICATE_BEGIN = b"-----BEGIN CERTIFICATE-----"
CERTIFICATE_END = b"-----END CERTIFICATE-----"
PEM_BEGIN = b"-----BEGIN "
PRIVATE_KEY_MARKERS = (
    PEM_BEGIN + b"PRIVATE KEY-----",
    PEM_BEGIN + b"ENCRYPTED PRIVATE KEY-----",
    PEM_BEGIN + b"RSA PRIVATE KEY-----",
    PEM_BEGIN + b"EC PRIVATE KEY-----",
)
REQUIRED_FILES = (
    "air-ca.crt",
    "air-ca.key",
    "ca.crt",
    "server.crt",
    "server.key",
    "client.crt",
    "client.key",
)
RFC1918_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class BootstrapError(RuntimeError):
    """The requested PKI bootstrap is unsafe or incomplete."""


@dataclass(frozen=True)
class BootstrapResult:
    certs_dir: Path
    idempotent: bool
    backup_dir: Path | None


def _canonical_absolute_path(raw: Path, *, description: str) -> Path:
    path = raw.expanduser()
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise BootstrapError(f"{description} must be an absolute canonical path: {path}")
    if path.is_symlink():
        raise BootstrapError(f"{description} must not be a symlink: {path}")
    # macOS exposes standard paths such as /var through root-owned symlinks.
    # Resolve those trusted platform aliases before inspecting each ancestor.
    return path.resolve(strict=False)


def _validate_private_ipv4(raw: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise BootstrapError("--wireguard-ip must be a valid IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not any(address in network for network in RFC1918_NETWORKS):
        raise BootstrapError("--wireguard-ip must be an RFC1918 IPv4 address")
    return address


def _validate_trusted_directory(path: Path, *, owner_only: bool, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"{description} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BootstrapError(f"{description} must be a real directory: {path}")
    if info.st_uid not in {0, os.getuid()}:
        raise BootstrapError(f"{description} is owned by an untrusted uid: {path}")
    permissions = stat.S_IMODE(info.st_mode)
    if owner_only and (info.st_uid != os.getuid() or permissions & 0o077):
        raise BootstrapError(f"{description} must be owned by this user and mode 0700: {path}")
    if permissions & 0o022 and not permissions & stat.S_ISVTX:
        raise BootstrapError(f"{description} is writable by an untrusted user: {path}")


def _validate_ancestors(path: Path, *, description: str) -> None:
    current = path
    while True:
        _validate_trusted_directory(current, owner_only=False, description=description)
        if current.parent == current:
            return
        current = current.parent


def _validate_owner_only_directory(path: Path) -> None:
    _validate_trusted_directory(path, owner_only=True, description="certificate directory")
    _validate_ancestors(path.parent, description="certificate directory ancestor")


def _validate_owner_only_file(path: Path, *, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"{description} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BootstrapError(f"{description} must be a regular, non-symlink file: {path}")
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        raise BootstrapError(f"{description} must be singly linked and owned by this user: {path}")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise BootstrapError(f"{description} must have mode 0600: {path}")


def _validate_owner_only_tree(path: Path, *, action: str) -> None:
    _validate_owner_only_directory(path)
    for child in path.rglob("*"):
        info = child.lstat()
        permissions = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or permissions & 0o077:
            raise BootstrapError(f"refusing to {action} unsafe PKI entry: {child}")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise BootstrapError(f"refusing to {action} hard-linked PKI entry: {child}")
        elif not stat.S_ISDIR(info.st_mode):
            raise BootstrapError(f"refusing to {action} unsupported PKI entry: {child}")


def _validate_public_input(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"legacy client CA does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BootstrapError(f"legacy client CA must be a regular, non-symlink file: {path}")
    if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise BootstrapError(f"legacy client CA must not be writable by an untrusted user: {path}")
    _validate_ancestors(path.parent, description="legacy client CA ancestor")


def _resolve_openssl(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise BootstrapError(f"OpenSSL path must be absolute and canonical: {path}")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise BootstrapError(f"OpenSSL is unavailable: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise BootstrapError(f"OpenSSL is not an executable regular file: {resolved}")
    if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise BootstrapError(f"OpenSSL is writable by an untrusted user: {resolved}")
    current = resolved.parent
    while True:
        ancestor = current.lstat()
        if stat.S_ISLNK(ancestor.st_mode) or not stat.S_ISDIR(ancestor.st_mode):
            raise BootstrapError(f"OpenSSL has a non-directory ancestor: {current}")
        if ancestor.st_uid not in {0, os.getuid()}:
            raise BootstrapError(f"OpenSSL has an ancestor owned by an untrusted uid: {current}")
        permissions = stat.S_IMODE(ancestor.st_mode)
        if permissions & 0o002 and not permissions & stat.S_ISVTX:
            raise BootstrapError(f"OpenSSL has a world-writable ancestor: {current}")
        if permissions & 0o020 and ancestor.st_uid != os.getuid():
            raise BootstrapError(f"OpenSSL has a group-writable root-owned ancestor: {current}")
        if current.parent == current:
            break
        current = current.parent
    return resolved


def _openssl(
    binary: Path,
    *arguments: str | Path,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = [str(binary), *(str(argument) for argument in arguments)]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f"OpenSSL command could not complete: {command[1]}") from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        suffix = f": {detail[-1][:300]}" if detail else ""
        raise BootstrapError(f"OpenSSL {command[1]} failed{suffix}")
    return result


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _secure_generated_file(path: Path, *, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"OpenSSL did not create {description}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise BootstrapError(f"OpenSSL created an unsafe {description}: {path}")
    os.chmod(path, 0o600)
    _validate_owner_only_file(path, description=description)


def _normalize_public_certificate(binary: Path, path: Path, *, description: str) -> bytes:
    raw = path.read_bytes()
    if any(marker in raw for marker in PRIVATE_KEY_MARKERS):
        raise BootstrapError(f"{description} must not contain private-key material")
    if raw.count(CERTIFICATE_BEGIN) != 1 or raw.count(CERTIFICATE_END) != 1:
        raise BootstrapError(f"{description} must contain exactly one PEM certificate")
    normalized = _openssl(binary, "x509", "-in", path, "-outform", "PEM").stdout
    if normalized.count(CERTIFICATE_BEGIN) != 1:
        raise BootstrapError(f"unable to normalize {description}")
    return normalized.rstrip() + b"\n"


def _validate_self_signed_ca(binary: Path, path: Path, *, description: str) -> None:
    _openssl(binary, "verify", "-CAfile", path, path)
    _openssl(binary, "x509", "-in", path, "-noout", "-checkend", "86400")
    constraints = _openssl(binary, "x509", "-in", path, "-noout", "-ext", "basicConstraints")
    if b"CA:TRUE" not in constraints.stdout.replace(b" ", b""):
        raise BootstrapError(f"{description} must be a CA certificate")


def _public_key_digest(binary: Path, *, certificate: Path | None = None, key: Path | None = None) -> bytes:
    if (certificate is None) == (key is None):
        raise AssertionError("provide exactly one of certificate or key")
    if certificate is not None:
        public_pem = _openssl(binary, "x509", "-in", certificate, "-pubkey", "-noout").stdout
        public_der = _openssl(binary, "pkey", "-pubin", "-outform", "DER", input_bytes=public_pem).stdout
    else:
        assert key is not None
        public_der = _openssl(binary, "pkey", "-in", key, "-pubout", "-outform", "DER").stdout
    return hashlib.sha256(public_der).digest()


def _validate_key_pair(binary: Path, certificate: Path, key: Path, *, description: str) -> None:
    if _public_key_digest(binary, certificate=certificate) != _public_key_digest(binary, key=key):
        raise BootstrapError(f"{description} certificate and private key do not match")


def _validate_leaf_certificates(binary: Path, certs_dir: Path, wireguard_ip: ipaddress.IPv4Address) -> None:
    air_ca = certs_dir / "air-ca.crt"
    server_cert = certs_dir / "server.crt"
    client_cert = certs_dir / "client.crt"

    _validate_key_pair(binary, air_ca, certs_dir / "air-ca.key", description="Air CA")
    _validate_key_pair(binary, server_cert, certs_dir / "server.key", description="server")
    _validate_key_pair(binary, client_cert, certs_dir / "client.key", description="local client")
    _validate_self_signed_ca(binary, air_ca, description="Air CA")

    _openssl(binary, "x509", "-in", server_cert, "-noout", "-checkip", wireguard_ip)
    _openssl(binary, "x509", "-in", server_cert, "-noout", "-checkend", "86400")
    _openssl(
        binary,
        "verify",
        "-CAfile",
        air_ca,
        "-purpose",
        "sslserver",
        "-verify_ip",
        wireguard_ip,
        server_cert,
    )
    if _openssl(binary, "verify", "-CAfile", air_ca, "-purpose", "sslclient", server_cert, check=False).returncode == 0:
        raise BootstrapError("server certificate must have serverAuth-only EKU")

    _openssl(binary, "x509", "-in", client_cert, "-noout", "-checkend", "86400")
    _openssl(binary, "verify", "-CAfile", air_ca, "-purpose", "sslclient", client_cert)
    if _openssl(binary, "verify", "-CAfile", air_ca, "-purpose", "sslserver", client_cert, check=False).returncode == 0:
        raise BootstrapError("local client certificate must have clientAuth-only EKU")
    _openssl(binary, "verify", "-CAfile", certs_dir / "ca.crt", "-purpose", "sslclient", client_cert)


def _expected_trust_bundle(binary: Path, certs_dir: Path, legacy_client_ca: Path | None) -> bytes:
    air_ca = _normalize_public_certificate(binary, certs_dir / "air-ca.crt", description="Air CA")
    if legacy_client_ca is None:
        return air_ca
    _validate_public_input(legacy_client_ca)
    legacy = _normalize_public_certificate(binary, legacy_client_ca, description="legacy client CA")
    _openssl(binary, "verify", "-CAfile", legacy_client_ca, legacy_client_ca)
    _openssl(binary, "x509", "-in", legacy_client_ca, "-noout", "-checkend", "86400")
    purposes = _openssl(binary, "x509", "-in", legacy_client_ca, "-noout", "-purpose").stdout
    if b"SSL client CA : Yes" not in purposes:
        raise BootstrapError("legacy client CA is not valid for SSL client certificate issuance")
    if hashlib.sha256(legacy).digest() == hashlib.sha256(air_ca).digest():
        raise BootstrapError("legacy client CA must be distinct from the Air CA")
    return air_ca + legacy


def validate_pki(
    *,
    certs_dir: Path,
    openssl_binary: Path,
    wireguard_ip: ipaddress.IPv4Address,
    legacy_client_ca: Path | None,
) -> None:
    certs_dir = _canonical_absolute_path(certs_dir, description="certificate directory")
    openssl_binary = _resolve_openssl(openssl_binary)
    if legacy_client_ca is not None:
        legacy_client_ca = _canonical_absolute_path(legacy_client_ca, description="legacy client CA")
    _validate_owner_only_tree(certs_dir, action="validate")
    for name in REQUIRED_FILES:
        _validate_owner_only_file(certs_dir / name, description=name)
    expected_bundle = _expected_trust_bundle(openssl_binary, certs_dir, legacy_client_ca)
    actual_bundle = certs_dir.joinpath("ca.crt").read_bytes()
    if actual_bundle != expected_bundle:
        raise BootstrapError("ca.crt does not match the requested Air/legacy client trust bundle")
    _validate_leaf_certificates(openssl_binary, certs_dir, wireguard_ip)


def _serial() -> str:
    return f"0x{secrets.randbits(159) | 1:040x}"


def _generate_pki(
    *,
    staging_dir: Path,
    openssl_binary: Path,
    wireguard_ip: ipaddress.IPv4Address,
    legacy_client_ca: Path | None,
) -> None:
    air_ca_cert = staging_dir / "air-ca.crt"
    air_ca_key = staging_dir / "air-ca.key"
    server_cert = staging_dir / "server.crt"
    server_key = staging_dir / "server.key"
    server_csr = staging_dir / ".server.csr"
    server_extensions = staging_dir / ".server-extensions.cnf"
    client_cert = staging_dir / "client.crt"
    client_key = staging_dir / "client.key"
    client_csr = staging_dir / ".client.csr"
    client_extensions = staging_dir / ".client-extensions.cnf"

    _write_private_file(
        server_extensions,
        (
            "[v3_server]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName=IP:{wireguard_ip}\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        ).encode(),
    )
    _write_private_file(
        client_extensions,
        (
            b"[v3_client]\n"
            b"basicConstraints=critical,CA:FALSE\n"
            b"keyUsage=critical,digitalSignature,keyEncipherment\n"
            b"extendedKeyUsage=clientAuth\n"
            b"subjectKeyIdentifier=hash\n"
            b"authorityKeyIdentifier=keyid,issuer\n"
        ),
    )

    _openssl(
        openssl_binary,
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-sha256",
        "-days",
        str(CA_DAYS),
        "-subj",
        "/CN=Air Temporary Edge CA/O=Portfolio/OU=Infrastructure",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-keyout",
        air_ca_key,
        "-out",
        air_ca_cert,
    )
    _openssl(
        openssl_binary,
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        f"/CN={wireguard_ip}/O=Portfolio/OU=Air Edge",
        "-keyout",
        server_key,
        "-out",
        server_csr,
    )
    _openssl(
        openssl_binary,
        "x509",
        "-req",
        "-sha256",
        "-days",
        str(LEAF_DAYS),
        "-in",
        server_csr,
        "-CA",
        air_ca_cert,
        "-CAkey",
        air_ca_key,
        "-set_serial",
        _serial(),
        "-extfile",
        server_extensions,
        "-extensions",
        "v3_server",
        "-out",
        server_cert,
    )
    _openssl(
        openssl_binary,
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        "/CN=Air Edge Local Client/O=Portfolio/OU=Admin",
        "-keyout",
        client_key,
        "-out",
        client_csr,
    )
    _openssl(
        openssl_binary,
        "x509",
        "-req",
        "-sha256",
        "-days",
        str(LEAF_DAYS),
        "-in",
        client_csr,
        "-CA",
        air_ca_cert,
        "-CAkey",
        air_ca_key,
        "-set_serial",
        _serial(),
        "-extfile",
        client_extensions,
        "-extensions",
        "v3_client",
        "-out",
        client_cert,
    )

    for path in (air_ca_cert, air_ca_key, server_cert, server_key, client_cert, client_key):
        _secure_generated_file(path, description=path.name)
    trust_bundle = _expected_trust_bundle(openssl_binary, staging_dir, legacy_client_ca)
    _write_private_file(staging_dir / "ca.crt", trust_bundle)

    for temporary in (server_csr, server_extensions, client_csr, client_extensions):
        temporary.unlink(missing_ok=True)


def _validate_rotation_source(path: Path) -> None:
    _validate_owner_only_tree(path, action="rotate")


def _backup_path(certs_dir: Path) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = certs_dir.with_name(f"{certs_dir.name}.backup-{timestamp}")
    counter = 1
    while candidate.exists():
        candidate = certs_dir.with_name(f"{certs_dir.name}.backup-{timestamp}-{counter}")
        counter += 1
    return candidate


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def bootstrap_pki(
    *,
    certs_dir: Path = DEFAULT_CERTS_DIR,
    openssl_binary: Path = DEFAULT_OPENSSL,
    wireguard_ip: str = DEFAULT_WIREGUARD_IP,
    legacy_client_ca: Path | None = None,
    rotate: bool = False,
) -> BootstrapResult:
    certs_dir = _canonical_absolute_path(certs_dir, description="certificate directory")
    openssl_binary = _resolve_openssl(openssl_binary)
    address = _validate_private_ipv4(wireguard_ip)
    if legacy_client_ca is not None:
        legacy_client_ca = _canonical_absolute_path(legacy_client_ca, description="legacy client CA")
        _validate_public_input(legacy_client_ca)
        if legacy_client_ca.is_relative_to(certs_dir):
            raise BootstrapError("legacy client CA must be stored outside the managed certificate directory")

    certs_dir.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _validate_ancestors(certs_dir.parent, description="certificate directory ancestor")

    if certs_dir.exists() and not rotate:
        try:
            validate_pki(
                certs_dir=certs_dir,
                openssl_binary=openssl_binary,
                wireguard_ip=address,
                legacy_client_ca=legacy_client_ca,
            )
        except BootstrapError as exc:
            raise BootstrapError(
                "existing PKI is incomplete or incompatible; refusing to overwrite it "
                "(review it, then use --rotate for a backed-up replacement)"
            ) from exc
        return BootstrapResult(certs_dir=certs_dir, idempotent=True, backup_dir=None)
    if certs_dir.exists():
        _validate_rotation_source(certs_dir)

    previous_umask = os.umask(0o077)
    staging_dir: Path | None = None
    backup_dir: Path | None = None
    installed = False
    try:
        staging_dir = Path(tempfile.mkdtemp(prefix=f".{certs_dir.name}.staging-", dir=certs_dir.parent))
        os.chmod(staging_dir, 0o700)
        _generate_pki(
            staging_dir=staging_dir,
            openssl_binary=openssl_binary,
            wireguard_ip=address,
            legacy_client_ca=legacy_client_ca,
        )
        validate_pki(
            certs_dir=staging_dir,
            openssl_binary=openssl_binary,
            wireguard_ip=address,
            legacy_client_ca=legacy_client_ca,
        )
        try:
            if certs_dir.exists():
                backup_dir = _backup_path(certs_dir)
                os.replace(certs_dir, backup_dir)
                _fsync_directory(certs_dir.parent)
            os.replace(staging_dir, certs_dir)
            installed = True
            _fsync_directory(certs_dir.parent)
            validate_pki(
                certs_dir=certs_dir,
                openssl_binary=openssl_binary,
                wireguard_ip=address,
                legacy_client_ca=legacy_client_ca,
            )
        except (BootstrapError, OSError):
            if installed and certs_dir.exists():
                os.replace(certs_dir, staging_dir)
                installed = False
            if backup_dir is not None and not certs_dir.exists():
                os.replace(backup_dir, certs_dir)
                backup_dir = None
            _fsync_directory(certs_dir.parent)
            raise
    finally:
        os.umask(previous_umask)
        if not installed and staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir)

    return BootstrapResult(certs_dir=certs_dir, idempotent=False, backup_dir=backup_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certs-dir", default=str(DEFAULT_CERTS_DIR), help="Owner-only Air certificate directory")
    parser.add_argument("--openssl", default=str(DEFAULT_OPENSSL), help="Absolute OpenSSL executable path")
    parser.add_argument("--wireguard-ip", default=DEFAULT_WIREGUARD_IP, help="Air WireGuard IPv4 SAN")
    parser.add_argument(
        "--legacy-client-ca",
        help="Optional public legacy Clockwork CA PEM to append to the client trust bundle",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Replace existing owner-only PKI after moving it to a timestamped local backup",
    )
    args = parser.parse_args(argv)
    try:
        result = bootstrap_pki(
            certs_dir=Path(args.certs_dir),
            openssl_binary=Path(args.openssl),
            wireguard_ip=args.wireguard_ip,
            legacy_client_ca=Path(args.legacy_client_ca) if args.legacy_client_ca else None,
            rotate=args.rotate,
        )
    except (BootstrapError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.idempotent:
        print(f"validated existing Air PKI; no changes made: {result.certs_dir}")
    else:
        print(f"created validated owner-only Air PKI: {result.certs_dir}")
        if result.backup_dir is not None:
            print(f"previous owner-only PKI retained at: {result.backup_dir}")
    print("private keys were not printed, exported, or installed into Keychain")
    print("activation: unchanged (no Caddy or launchctl operations performed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
