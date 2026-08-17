#!/usr/bin/env python3
"""Issue owner-only Apple profiles for the temporary macOS Air edge.

This tool is deliberately local and inert. It creates a distinct Air-CA-signed
client identity for each selected device and embeds that encrypted PKCS#12
identity plus the public Air root certificate in an Apple configuration
profile. It never installs a profile, imports Keychain material, changes
WireGuard, or activates a service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import bootstrap_macos_air_pki as air_pki  # noqa: E402

DEFAULT_CERTS_DIR = air_pki.DEFAULT_CERTS_DIR
DEFAULT_OUTPUT_ROOT = Path.home() / ".config" / "wiring-harness" / "air-profiles"
DEFAULT_OPENSSL = air_pki.DEFAULT_OPENSSL
PROFILE_IDENTIFIER_PREFIX = "local.wiring-harness.air"
PROFILE_SCHEMA_VERSION = 1
ROOT_MANIFEST_NAME = "manifest.json"
STORED_CA_NAME = "air-ca.crt"
IDENTITIES_DIR_NAME = "identities"
PROFILES_DIR_NAME = "profiles"
CLIENT_DAYS = air_pki.LEAF_DAYS
FINDER_METADATA_NAME = ".DS_Store"
ALLOWED_FINDER_METADATA_PATHS = frozenset(
    {
        Path(FINDER_METADATA_NAME),
        Path(PROFILES_DIR_NAME) / FINDER_METADATA_NAME,
    }
)


class ProfileError(RuntimeError):
    """The requested profile operation is unsafe or incomplete."""


@dataclass(frozen=True)
class DeviceSpec:
    slug: str
    display_name: str

    @property
    def common_name(self) -> str:
        return f"Air Edge {self.display_name} Client"

    @property
    def profile_identifier(self) -> str:
        return f"{PROFILE_IDENTIFIER_PREFIX}.{self.slug}"

    @property
    def profile_file(self) -> str:
        return f"air-{self.slug}.mobileconfig"


DEVICES = {
    "mini": DeviceSpec(slug="mini", display_name="Mini"),
    "pro": DeviceSpec(slug="pro", display_name="Pro"),
}


@dataclass(frozen=True)
class ProfileResult:
    output_root: Path
    selected_devices: tuple[str, ...]
    generated_devices: tuple[str, ...]
    preserved_devices: tuple[str, ...]
    idempotent: bool
    backup_dir: Path | None


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stable_uuid(label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"local.wiring-harness.air:{label}")).upper()


def _private_write(path: Path, content: bytes) -> None:
    try:
        air_pki._write_private_file(path, content)
    except (OSError, air_pki.BootstrapError) as exc:
        raise ProfileError(f"could not write owner-only artifact: {path.name}") from exc


def _validate_input_pki(certs_dir: Path, openssl_binary: Path) -> tuple[Path, Path, Path]:
    try:
        certs_dir = air_pki._canonical_absolute_path(certs_dir, description="Air certificate directory")
        openssl_binary = air_pki._resolve_openssl(openssl_binary)
        air_pki._validate_owner_only_tree(certs_dir, action="issue device profiles from")
        ca_cert = certs_dir / "air-ca.crt"
        ca_key = certs_dir / "air-ca.key"
        trust_bundle = certs_dir / "ca.crt"
        air_pki._validate_owner_only_file(ca_cert, description="Air CA certificate")
        air_pki._validate_owner_only_file(ca_key, description="Air CA private key")
        air_pki._validate_owner_only_file(trust_bundle, description="live client trust bundle")
        air_pki._normalize_public_certificate(openssl_binary, ca_cert, description="Air CA")
        air_pki._validate_self_signed_ca(openssl_binary, ca_cert, description="Air CA")
        air_pki._validate_key_pair(openssl_binary, ca_cert, ca_key, description="Air CA")
        air_der = _certificate_der(openssl_binary, ca_cert)
        bundle_certificates = _certificate_bundle_der(openssl_binary, trust_bundle)
        if bundle_certificates.count(air_der) != 1:
            raise ProfileError("live ca.crt must contain the exact Air CA exactly once")
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc
    return certs_dir, openssl_binary, ca_cert


def _canonical_output_root(raw: Path, certs_dir: Path) -> Path:
    try:
        output_root = air_pki._canonical_absolute_path(raw, description="profile output directory")
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc
    if output_root == certs_dir or output_root.is_relative_to(certs_dir) or certs_dir.is_relative_to(output_root):
        raise ProfileError("profile output and Air certificate directories must be disjoint")
    return output_root


def _validate_private_file(path: Path, description: str) -> None:
    try:
        air_pki._validate_owner_only_file(path, description=description)
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc


def _validate_profile_tree(
    path: Path,
    *,
    action: str,
    allowed_finder_metadata: frozenset[Path] = frozenset(),
) -> None:
    """Validate owner-only profile state while tolerating inert Finder metadata."""

    try:
        air_pki._validate_owner_only_directory(path)
        for child in path.rglob("*"):
            info = child.lstat()
            permissions = stat.S_IMODE(info.st_mode)
            if child.relative_to(path) in allowed_finder_metadata:
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or permissions not in {0o600, 0o644}
                ):
                    raise air_pki.BootstrapError(f"refusing to {action} unsafe Finder metadata: {child}")
                continue
            if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or permissions & 0o077:
                raise air_pki.BootstrapError(f"refusing to {action} unsafe profile entry: {child}")
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise air_pki.BootstrapError(f"refusing to {action} hard-linked profile entry: {child}")
            elif not stat.S_ISDIR(info.st_mode):
                raise air_pki.BootstrapError(f"refusing to {action} unsupported profile entry: {child}")
    except (OSError, air_pki.BootstrapError) as exc:
        raise ProfileError(str(exc)) from exc


def _scan_output_root(output_root: Path) -> tuple[set[str], set[str]]:
    _validate_profile_tree(
        output_root,
        action="use",
        allowed_finder_metadata=ALLOWED_FINDER_METADATA_PATHS,
    )
    allowed_root_entries = {ROOT_MANIFEST_NAME, STORED_CA_NAME, IDENTITIES_DIR_NAME, PROFILES_DIR_NAME}
    for child in output_root.iterdir():
        if child.name == FINDER_METADATA_NAME:
            continue
        if child.name not in allowed_root_entries:
            raise ProfileError(f"unexpected entry in profile output directory: {child.name}")
        if child.name in {ROOT_MANIFEST_NAME, STORED_CA_NAME} and not child.is_file():
            raise ProfileError(f"{child.name} must be a regular file")
        if child.name not in {ROOT_MANIFEST_NAME, STORED_CA_NAME} and not child.is_dir():
            raise ProfileError(f"{child.name} must be an owner-only directory")

    identity_slugs: set[str] = set()
    identities_dir = output_root / IDENTITIES_DIR_NAME
    if identities_dir.exists():
        for child in identities_dir.iterdir():
            if child.name not in DEVICES or not child.is_dir():
                raise ProfileError(f"unexpected identity-state entry: {child.name}")
            identity_slugs.add(child.name)

    profile_slugs: set[str] = set()
    profiles_dir = output_root / PROFILES_DIR_NAME
    if profiles_dir.exists():
        expected_profiles = {spec.profile_file: slug for slug, spec in DEVICES.items()}
        for child in profiles_dir.iterdir():
            if child.name == FINDER_METADATA_NAME:
                continue
            slug = expected_profiles.get(child.name)
            if slug is None or not child.is_file():
                raise ProfileError(f"unexpected profile-delivery entry: {child.name}")
            profile_slugs.add(slug)
    return identity_slugs, profile_slugs


def _load_json(path: Path, description: str) -> dict[str, Any]:
    _validate_private_file(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"{description} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProfileError(f"{description} must be a JSON object: {path}")
    return value


def _certificate_der(openssl_binary: Path, certificate: Path) -> bytes:
    return air_pki._openssl(openssl_binary, "x509", "-in", certificate, "-outform", "DER").stdout


def _certificate_bundle_der(openssl_binary: Path, bundle: Path) -> list[bytes]:
    """Parse a PEM-only certificate bundle without accepting hidden material."""

    try:
        raw = bundle.read_bytes()
    except OSError as exc:
        raise air_pki.BootstrapError(f"could not read certificate bundle: {bundle}") from exc
    if any(marker in raw for marker in air_pki.PRIVATE_KEY_MARKERS):
        raise air_pki.BootstrapError("live ca.crt must not contain private-key material")

    blocks: list[bytes] = []
    cursor = 0
    while cursor < len(raw):
        begin = raw.find(air_pki.CERTIFICATE_BEGIN, cursor)
        if begin < 0:
            if raw[cursor:].strip():
                raise air_pki.BootstrapError("live ca.crt must contain only PEM certificates")
            break
        if raw[cursor:begin].strip():
            raise air_pki.BootstrapError("live ca.crt must contain only PEM certificates")
        end = raw.find(air_pki.CERTIFICATE_END, begin + len(air_pki.CERTIFICATE_BEGIN))
        nested = raw.find(air_pki.CERTIFICATE_BEGIN, begin + len(air_pki.CERTIFICATE_BEGIN))
        if end < 0 or (nested >= 0 and nested < end):
            raise air_pki.BootstrapError("live ca.crt contains a malformed PEM certificate")
        end += len(air_pki.CERTIFICATE_END)
        blocks.append(raw[begin:end] + b"\n")
        cursor = end
    if not blocks:
        raise air_pki.BootstrapError("live ca.crt contains no certificates")

    certificates: list[bytes] = []
    with tempfile.TemporaryDirectory(prefix="air-trust-bundle-") as temporary:
        temporary_path = Path(temporary)
        os.chmod(temporary_path, 0o700)
        for index, block in enumerate(blocks):
            certificate = temporary_path / f"certificate-{index}.crt"
            air_pki._write_private_file(certificate, block)
            certificates.append(_certificate_der(openssl_binary, certificate))
    return certificates


def _certificate_time(openssl_value: str) -> datetime:
    try:
        return datetime.strptime(openssl_value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ProfileError("OpenSSL returned an unsupported certificate validity timestamp") from exc


def _certificate_metadata(openssl_binary: Path, certificate: Path) -> dict[str, str]:
    result = air_pki._openssl(
        openssl_binary,
        "x509",
        "-in",
        certificate,
        "-noout",
        "-serial",
        "-subject",
        "-issuer",
        "-startdate",
        "-enddate",
        "-nameopt",
        "RFC2253",
    )
    metadata: dict[str, str] = {}
    for raw_line in result.stdout.decode("utf-8", errors="strict").splitlines():
        key, separator, value = raw_line.partition("=")
        if not separator:
            raise ProfileError("OpenSSL returned malformed certificate metadata")
        metadata[key.strip()] = value.strip()
    required = {"serial", "subject", "issuer", "notBefore", "notAfter"}
    if not required.issubset(metadata):
        raise ProfileError("OpenSSL omitted required certificate metadata")
    return {key: metadata[key] for key in sorted(required)}


def _device_paths(identity_directory: Path, profile_directory: Path, spec: DeviceSpec) -> dict[str, Path]:
    return {
        "cert": identity_directory / "client.crt",
        "key": identity_directory / "client.key",
        "p12": identity_directory / "client.p12",
        "passphrase": identity_directory / "client.p12.passphrase",
        "profile": profile_directory / spec.profile_file,
        "manifest": identity_directory / ROOT_MANIFEST_NAME,
    }


def _load_passphrase(path: Path) -> str:
    _validate_private_file(path, "PKCS#12 passphrase file")
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProfileError("PKCS#12 passphrase file must contain ASCII text") from exc
    if raw.count("\n") > 1 or ("\n" in raw and not raw.endswith("\n")):
        raise ProfileError("PKCS#12 passphrase file must contain exactly one line")
    passphrase = raw.rstrip("\n")
    if len(passphrase) < 24 or any(character.isspace() for character in passphrase):
        raise ProfileError("PKCS#12 passphrase file is empty or malformed")
    return passphrase


def _build_mobileconfig(*, spec: DeviceSpec, ca_der: bytes, p12_bytes: bytes) -> bytes:
    # UUIDs intentionally remain stable across certificate rotation so Apple
    # treats a new profile for the same device/role as a replacement.
    profile_identifier = spec.profile_identifier
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": profile_identifier,
        "PayloadUUID": _stable_uuid(f"{spec.slug}:profile"),
        "PayloadDisplayName": f"Air Private Edge ({spec.display_name})",
        "PayloadDescription": (f"Installs Air CA trust and the distinct {spec.display_name} mTLS client identity."),
        "PayloadOrganization": "Portfolio",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [
            {
                "PayloadType": "com.apple.security.root",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"{profile_identifier}.root",
                "PayloadUUID": _stable_uuid(f"{spec.slug}:root"),
                "PayloadDisplayName": "Air Temporary Edge CA",
                "PayloadDescription": "Installs the root certificate for the temporary Air private edge.",
                "PayloadCertificateFileName": "air-ca.crt",
                "PayloadContent": ca_der,
            },
            {
                "PayloadType": "com.apple.security.pkcs12",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"{profile_identifier}.identity",
                "PayloadUUID": _stable_uuid(f"{spec.slug}:identity"),
                "PayloadDisplayName": f"Air mTLS Client Identity ({spec.display_name})",
                "PayloadDescription": "Installs the client identity required by Air private HTTPS services.",
                "PayloadCertificateFileName": "client.p12",
                "PayloadContent": p12_bytes,
            },
        ],
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)


def _expected_device_manifest(
    *, spec: DeviceSpec, paths: dict[str, Path], openssl_binary: Path, ca_cert: Path
) -> dict[str, Any]:
    metadata = _certificate_metadata(openssl_binary, paths["cert"])
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "device": spec.slug,
        "display_name": spec.display_name,
        "profile_identifier": spec.profile_identifier,
        "artifacts": {
            "certificate": paths["cert"].name,
            "private_key": paths["key"].name,
            "pkcs12": paths["p12"].name,
            "pkcs12_passphrase": paths["passphrase"].name,
            "delivery_mobileconfig": f"{PROFILES_DIR_NAME}/{paths['profile'].name}",
        },
        "digests": {
            "air_ca_sha256": _sha256(_certificate_der(openssl_binary, ca_cert)),
            "client_certificate_sha256": _sha256(_certificate_der(openssl_binary, paths["cert"])),
            "pkcs12_sha256": _sha256(paths["p12"].read_bytes()),
            "mobileconfig_sha256": _sha256(paths["profile"].read_bytes()),
        },
        "certificate": metadata,
        "password_embedded_in_mobileconfig": False,
        "installation_performed": False,
    }


def _validate_device_directory(
    *,
    identity_directory: Path,
    profile_directory: Path,
    spec: DeviceSpec,
    openssl_binary: Path,
    ca_cert: Path,
    allow_time_invalid: bool = False,
) -> dict[str, Any]:
    _validate_profile_tree(identity_directory, action="use")
    paths = _device_paths(identity_directory, profile_directory, spec)
    expected_names = {paths[key].name for key in ("cert", "key", "p12", "passphrase", "manifest")}
    actual_names = {path.name for path in identity_directory.iterdir()}
    if actual_names != expected_names:
        raise ProfileError(f"{spec.display_name} profile state is incomplete or contains unexpected artifacts")
    for description, path in paths.items():
        _validate_private_file(path, f"{spec.display_name} {description} artifact")

    passphrase = _load_passphrase(paths["passphrase"])
    del passphrase
    pkcs12_private_key = b""
    try:
        air_pki._validate_key_pair(openssl_binary, paths["cert"], paths["key"], description=spec.common_name)
        metadata = _certificate_metadata(openssl_binary, paths["cert"])
        renewal_check = air_pki._openssl(
            openssl_binary,
            "x509",
            "-in",
            paths["cert"],
            "-noout",
            "-checkend",
            "86400",
            check=False,
        )
        client_check = air_pki._openssl(
            openssl_binary,
            "verify",
            "-CAfile",
            ca_cert,
            "-purpose",
            "sslclient",
            paths["cert"],
            check=False,
        )
        time_relaxed = False
        if renewal_check.returncode != 0:
            if not allow_time_invalid:
                raise ProfileError(f"{spec.display_name} certificate is expired or too close to expiry")
            if client_check.returncode != 0:
                now = datetime.now(UTC)
                not_before = _certificate_time(metadata["notBefore"])
                not_after = _certificate_time(metadata["notAfter"])
                if not_before > now or not_after > now:
                    raise ProfileError(f"{spec.display_name} identity validation failed")
                client_check = air_pki._openssl(
                    openssl_binary,
                    "verify",
                    "-no_check_time",
                    "-CAfile",
                    ca_cert,
                    "-purpose",
                    "sslclient",
                    paths["cert"],
                    check=False,
                )
                time_relaxed = True
        if client_check.returncode != 0:
            raise ProfileError(f"{spec.display_name} identity validation failed")
        server_arguments: list[str | Path] = ["verify"]
        if time_relaxed:
            server_arguments.append("-no_check_time")
        server_arguments.extend(["-CAfile", ca_cert, "-purpose", "sslserver", paths["cert"]])
        server_check = air_pki._openssl(
            openssl_binary,
            *server_arguments,
            check=False,
        )
        if server_check.returncode == 0:
            raise ProfileError(f"{spec.display_name} certificate must have clientAuth-only EKU")
        subject = air_pki._openssl(
            openssl_binary,
            "x509",
            "-in",
            paths["cert"],
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ).stdout.decode("utf-8", errors="strict")
        if f"CN={spec.common_name}" not in subject:
            raise ProfileError(f"{spec.display_name} certificate subject does not match the device")
        air_pki._openssl(
            openssl_binary,
            "pkcs12",
            "-in",
            paths["p12"],
            "-passin",
            f"file:{paths['passphrase']}",
            "-noout",
        )
        pkcs12_leaf = air_pki._openssl(
            openssl_binary,
            "pkcs12",
            "-in",
            paths["p12"],
            "-passin",
            f"file:{paths['passphrase']}",
            "-clcerts",
            "-nokeys",
        ).stdout
        pkcs12_private_key = air_pki._openssl(
            openssl_binary,
            "pkcs12",
            "-in",
            paths["p12"],
            "-passin",
            f"file:{paths['passphrase']}",
            "-nocerts",
            "-nodes",
        ).stdout
    except air_pki.BootstrapError as exc:
        raise ProfileError(f"{spec.display_name} identity validation failed: {exc}") from exc
    private_key_count = sum(pkcs12_private_key.count(marker) for marker in air_pki.PRIVATE_KEY_MARKERS)
    if private_key_count != 1:
        pkcs12_private_key = b""
        raise ProfileError(f"{spec.display_name} PKCS#12 must contain exactly one private key")
    if pkcs12_leaf.count(air_pki.CERTIFICATE_BEGIN) != 1:
        pkcs12_private_key = b""
        raise ProfileError(f"{spec.display_name} PKCS#12 must contain exactly one client identity")
    try:
        pkcs12_public_der = air_pki._openssl(
            openssl_binary,
            "pkey",
            "-pubout",
            "-outform",
            "DER",
            input_bytes=pkcs12_private_key,
        ).stdout
    except air_pki.BootstrapError as exc:
        raise ProfileError(f"{spec.display_name} PKCS#12 private key is invalid") from exc
    finally:
        pkcs12_private_key = b""
    if hashlib.sha256(pkcs12_public_der).digest() != air_pki._public_key_digest(
        openssl_binary, certificate=paths["cert"]
    ):
        raise ProfileError(f"{spec.display_name} PKCS#12 private key does not match client.crt")
    with tempfile.TemporaryDirectory(prefix="air-profile-leaf-") as temporary:
        extracted = Path(temporary) / "client.crt"
        extracted.write_bytes(pkcs12_leaf)
        if _certificate_der(openssl_binary, extracted) != _certificate_der(openssl_binary, paths["cert"]):
            raise ProfileError(f"{spec.display_name} PKCS#12 identity does not match client.crt")

    try:
        profile = plistlib.loads(paths["profile"].read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ProfileError(f"{spec.display_name} mobileconfig is not a valid property list") from exc
    if not isinstance(profile, dict) or profile.get("PayloadIdentifier") != spec.profile_identifier:
        raise ProfileError(f"{spec.display_name} mobileconfig identifier is invalid")
    payloads = profile.get("PayloadContent")
    if not isinstance(payloads, list) or len(payloads) != 2:
        raise ProfileError(f"{spec.display_name} mobileconfig must contain exactly two payloads")
    payload_by_type = {payload.get("PayloadType"): payload for payload in payloads if isinstance(payload, dict)}
    if set(payload_by_type) != {"com.apple.security.root", "com.apple.security.pkcs12"}:
        raise ProfileError(f"{spec.display_name} mobileconfig payload types are invalid")
    root_payload = payload_by_type["com.apple.security.root"]
    identity_payload = payload_by_type["com.apple.security.pkcs12"]
    if root_payload.get("PayloadContent") != _certificate_der(openssl_binary, ca_cert):
        raise ProfileError(f"{spec.display_name} mobileconfig embeds the wrong Air CA")
    if identity_payload.get("PayloadContent") != paths["p12"].read_bytes():
        raise ProfileError(f"{spec.display_name} mobileconfig embeds the wrong PKCS#12 identity")
    forbidden_password_fields = {"Password", "PayloadPassword", "password", "payload_password"}
    if forbidden_password_fields.intersection(identity_payload):
        raise ProfileError(f"{spec.display_name} mobileconfig must not embed the PKCS#12 password")

    expected_manifest = _expected_device_manifest(
        spec=spec,
        paths=paths,
        openssl_binary=openssl_binary,
        ca_cert=ca_cert,
    )
    actual_manifest = _load_json(paths["manifest"], f"{spec.display_name} manifest")
    if actual_manifest != expected_manifest:
        raise ProfileError(f"{spec.display_name} manifest does not match its artifacts")
    return expected_manifest


def _expected_root_manifest(
    *, output_root: Path, devices: dict[str, dict[str, Any]], openssl_binary: Path, ca_cert: Path
) -> dict[str, Any]:
    entries = []
    for slug in sorted(devices):
        device_manifest = devices[slug]
        manifest_path = output_root / IDENTITIES_DIR_NAME / slug / ROOT_MANIFEST_NAME
        entries.append(
            {
                "device": slug,
                "display_name": DEVICES[slug].display_name,
                "identity_directory": f"{IDENTITIES_DIR_NAME}/{slug}",
                "delivery_profile": f"{PROFILES_DIR_NAME}/{DEVICES[slug].profile_file}",
                "manifest": f"{IDENTITIES_DIR_NAME}/{slug}/{ROOT_MANIFEST_NAME}",
                "manifest_sha256": _sha256(manifest_path.read_bytes()),
                "client_certificate_sha256": device_manifest["digests"]["client_certificate_sha256"],
            }
        )
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_set": "macos-air",
        "air_ca_certificate": STORED_CA_NAME,
        "air_ca_sha256": _sha256(_certificate_der(openssl_binary, ca_cert)),
        "devices": entries,
        "installation_performed": False,
    }


def validate_profile_set(
    *,
    output_root: Path,
    openssl_binary: Path,
    ca_cert: Path,
    renewal_devices: frozenset[str] = frozenset(),
) -> dict[str, dict[str, Any]]:
    if any(slug not in DEVICES for slug in renewal_devices):
        raise ProfileError("renewal validation contains an unsupported device")
    try:
        output_root = air_pki._canonical_absolute_path(output_root, description="profile output directory")
        ca_cert = air_pki._canonical_absolute_path(ca_cert, description="profile-set Air CA")
        air_pki._validate_self_signed_ca(openssl_binary, ca_cert, description="profile-set Air CA")
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc
    identity_slugs, profile_slugs = _scan_output_root(output_root)
    stored_ca = output_root / STORED_CA_NAME
    _validate_private_file(stored_ca, "stored profile-set Air CA")
    if _certificate_der(openssl_binary, stored_ca) != _certificate_der(openssl_binary, ca_cert):
        raise ProfileError("stored profile-set Air CA does not match the validation CA")
    if not identity_slugs:
        raise ProfileError("profile output directory contains no device identities")
    if identity_slugs != profile_slugs:
        raise ProfileError("profile delivery and private identity state are incomplete")
    device_manifests: dict[str, dict[str, Any]] = {}
    client_digests: set[str] = set()
    for slug in sorted(identity_slugs):
        manifest = _validate_device_directory(
            identity_directory=output_root / IDENTITIES_DIR_NAME / slug,
            profile_directory=output_root / PROFILES_DIR_NAME,
            spec=DEVICES[slug],
            openssl_binary=openssl_binary,
            ca_cert=ca_cert,
            allow_time_invalid=slug in renewal_devices,
        )
        digest = manifest["digests"]["client_certificate_sha256"]
        if digest in client_digests:
            raise ProfileError("device profiles must contain distinct client identities")
        client_digests.add(digest)
        device_manifests[slug] = manifest

    expected_root = _expected_root_manifest(
        output_root=output_root,
        devices=device_manifests,
        openssl_binary=openssl_binary,
        ca_cert=ca_cert,
    )
    actual_root = _load_json(output_root / ROOT_MANIFEST_NAME, "profile-set manifest")
    if actual_root != expected_root:
        raise ProfileError("profile-set manifest does not match its device artifacts")
    return device_manifests


def _secure_generated(path: Path, description: str) -> None:
    try:
        air_pki._secure_generated_file(path, description=description)
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc


def _generate_device(
    *,
    identity_directory: Path,
    profile_directory: Path,
    spec: DeviceSpec,
    openssl_binary: Path,
    ca_cert: Path,
    ca_key: Path,
    trust_bundle: Path,
) -> None:
    identity_directory.mkdir(mode=0o700)
    os.chmod(identity_directory, 0o700)
    paths = _device_paths(identity_directory, profile_directory, spec)
    csr = identity_directory / ".client.csr"
    extensions = identity_directory / ".client-extensions.cnf"
    _private_write(
        extensions,
        (
            b"[v3_client]\n"
            b"basicConstraints=critical,CA:FALSE\n"
            b"keyUsage=critical,digitalSignature,keyEncipherment\n"
            b"extendedKeyUsage=clientAuth\n"
            b"subjectKeyIdentifier=hash\n"
            b"authorityKeyIdentifier=keyid,issuer\n"
        ),
    )
    passphrase = secrets.token_urlsafe(32)
    _private_write(paths["passphrase"], f"{passphrase}\n".encode("ascii"))
    del passphrase
    try:
        air_pki._openssl(
            openssl_binary,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-subj",
            f"/CN={spec.common_name}/O=Portfolio/OU=Air Edge",
            "-keyout",
            paths["key"],
            "-out",
            csr,
        )
        air_pki._openssl(
            openssl_binary,
            "x509",
            "-req",
            "-sha256",
            "-days",
            str(CLIENT_DAYS),
            "-in",
            csr,
            "-CA",
            ca_cert,
            "-CAkey",
            ca_key,
            "-set_serial",
            air_pki._serial(),
            "-extfile",
            extensions,
            "-extensions",
            "v3_client",
            "-out",
            paths["cert"],
        )
        air_pki._openssl(
            openssl_binary,
            "pkcs12",
            "-export",
            "-name",
            spec.common_name,
            "-inkey",
            paths["key"],
            "-in",
            paths["cert"],
            "-certfile",
            ca_cert,
            "-out",
            paths["p12"],
            "-passout",
            f"file:{paths['passphrase']}",
        )
        air_pki._openssl(
            openssl_binary,
            "verify",
            "-CAfile",
            trust_bundle,
            "-purpose",
            "sslclient",
            paths["cert"],
        )
    except air_pki.BootstrapError as exc:
        raise ProfileError(f"could not issue {spec.display_name} identity: {exc}") from exc
    finally:
        csr.unlink(missing_ok=True)
        extensions.unlink(missing_ok=True)
    for key, path in paths.items():
        if key not in {"profile", "manifest", "passphrase"}:
            _secure_generated(path, f"{spec.display_name} {key} artifact")

    ca_der = _certificate_der(openssl_binary, ca_cert)
    profile = _build_mobileconfig(
        spec=spec,
        ca_der=ca_der,
        p12_bytes=paths["p12"].read_bytes(),
    )
    _private_write(paths["profile"], profile)
    manifest = _expected_device_manifest(
        spec=spec,
        paths=paths,
        openssl_binary=openssl_binary,
        ca_cert=ca_cert,
    )
    _private_write(paths["manifest"], (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _copy_device(*, source_identity: Path, target_identity: Path, source_profile: Path, target_profile: Path) -> None:
    shutil.copytree(source_identity, target_identity, symlinks=False, copy_function=shutil.copy2)
    for path in target_identity.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chmod(target_identity, 0o700)
    shutil.copy2(source_profile, target_profile)
    os.chmod(target_profile, 0o600)


def _write_root_manifest(*, output_root: Path, openssl_binary: Path, ca_cert: Path) -> None:
    identities_dir = output_root / IDENTITIES_DIR_NAME
    device_manifests = {
        slug: _load_json(identities_dir / slug / ROOT_MANIFEST_NAME, f"{DEVICES[slug].display_name} manifest")
        for slug in sorted(path.name for path in identities_dir.iterdir() if path.is_dir() and path.name in DEVICES)
    }
    manifest = _expected_root_manifest(
        output_root=output_root,
        devices=device_manifests,
        openssl_binary=openssl_binary,
        ca_cert=ca_cert,
    )
    _private_write(output_root / ROOT_MANIFEST_NAME, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())


def _fsync_directory(path: Path) -> None:
    try:
        air_pki._fsync_directory(path)
    except OSError as exc:
        raise ProfileError(f"could not sync profile directory metadata: {path}") from exc


def generate_profiles(
    *,
    certs_dir: Path = DEFAULT_CERTS_DIR,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    openssl_binary: Path = DEFAULT_OPENSSL,
    devices: tuple[str, ...] = ("mini", "pro"),
    rotate: bool = False,
) -> ProfileResult:
    selected = tuple(sorted(set(devices)))
    if not selected or any(slug not in DEVICES for slug in selected):
        raise ProfileError("at least one supported device (mini or pro) must be selected")
    certs_dir, openssl_binary, ca_cert = _validate_input_pki(certs_dir, openssl_binary)
    ca_key = certs_dir / "air-ca.key"
    output_root = _canonical_output_root(output_root, certs_dir)

    output_root.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        air_pki._validate_ancestors(output_root.parent, description="profile output ancestor")
    except air_pki.BootstrapError as exc:
        raise ProfileError(str(exc)) from exc

    existing: set[str] = set()
    if output_root.exists():
        stored_ca = output_root / STORED_CA_NAME
        _validate_private_file(stored_ca, "stored profile-set Air CA")
        existing_manifests = validate_profile_set(
            output_root=output_root,
            openssl_binary=openssl_binary,
            ca_cert=stored_ca,
            renewal_devices=frozenset(selected) if rotate else frozenset(),
        )
        existing = set(existing_manifests)
        ca_changed = _certificate_der(openssl_binary, stored_ca) != _certificate_der(openssl_binary, ca_cert)
        if ca_changed and not rotate:
            raise ProfileError("Air CA changed; use --rotate to replace every existing device identity")
        if ca_changed and not existing.issubset(selected):
            raise ProfileError("Air CA changed; --rotate must select every existing device identity")

    generated = tuple(slug for slug in selected if rotate or slug not in existing)
    preserved = tuple(sorted(existing - set(generated)))
    if not generated:
        return ProfileResult(
            output_root=output_root,
            selected_devices=selected,
            generated_devices=(),
            preserved_devices=preserved,
            idempotent=True,
            backup_dir=None,
        )

    previous_umask = os.umask(0o077)
    staging_root: Path | None = None
    backup_dir: Path | None = None
    installed = False
    try:
        staging_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
        os.chmod(staging_root, 0o700)
        identities_dir = staging_root / IDENTITIES_DIR_NAME
        profiles_dir = staging_root / PROFILES_DIR_NAME
        identities_dir.mkdir(mode=0o700)
        profiles_dir.mkdir(mode=0o700)
        _private_write(
            staging_root / STORED_CA_NAME,
            air_pki._normalize_public_certificate(openssl_binary, ca_cert, description="Air CA"),
        )
        for slug in preserved:
            _copy_device(
                source_identity=output_root / IDENTITIES_DIR_NAME / slug,
                target_identity=identities_dir / slug,
                source_profile=output_root / PROFILES_DIR_NAME / DEVICES[slug].profile_file,
                target_profile=profiles_dir / DEVICES[slug].profile_file,
            )
        for slug in generated:
            _generate_device(
                identity_directory=identities_dir / slug,
                profile_directory=profiles_dir,
                spec=DEVICES[slug],
                openssl_binary=openssl_binary,
                ca_cert=ca_cert,
                ca_key=ca_key,
                trust_bundle=certs_dir / "ca.crt",
            )
        _write_root_manifest(output_root=staging_root, openssl_binary=openssl_binary, ca_cert=ca_cert)
        validate_profile_set(output_root=staging_root, openssl_binary=openssl_binary, ca_cert=ca_cert)
        try:
            if output_root.exists():
                backup_dir = air_pki._backup_path(output_root)
                os.replace(output_root, backup_dir)
                _fsync_directory(output_root.parent)
            os.replace(staging_root, output_root)
            installed = True
            _fsync_directory(output_root.parent)
            validate_profile_set(output_root=output_root, openssl_binary=openssl_binary, ca_cert=ca_cert)
        except (OSError, ProfileError):
            if installed and output_root.exists():
                os.replace(output_root, staging_root)
                installed = False
            if backup_dir is not None and not output_root.exists():
                os.replace(backup_dir, output_root)
                backup_dir = None
            _fsync_directory(output_root.parent)
            raise
    finally:
        os.umask(previous_umask)
        if not installed and staging_root is not None and staging_root.exists():
            shutil.rmtree(staging_root)

    return ProfileResult(
        output_root=output_root,
        selected_devices=selected,
        generated_devices=generated,
        preserved_devices=preserved,
        idempotent=False,
        backup_dir=backup_dir,
    )


def _resolve_pbcopy(path: Path = Path("/usr/bin/pbcopy")) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ProfileError("pbcopy path must be absolute and canonical")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise ProfileError(f"pbcopy is unavailable: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise ProfileError(f"pbcopy is not an executable regular file: {resolved}")
    if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise ProfileError(f"pbcopy is writable by an untrusted user: {resolved}")
    return resolved


def _run_pbcopy(command: list[str], passphrase: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        input=passphrase,
        capture_output=True,
        timeout=10,
        check=False,
    )


def copy_passphrase(
    *,
    device: str,
    certs_dir: Path = DEFAULT_CERTS_DIR,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    openssl_binary: Path = DEFAULT_OPENSSL,
    pbcopy_binary: Path = Path("/usr/bin/pbcopy"),
) -> None:
    if device not in DEVICES:
        raise ProfileError("copy-passphrase requires device mini or pro")
    certs_dir, openssl_binary, ca_cert = _validate_input_pki(certs_dir, openssl_binary)
    output_root = _canonical_output_root(output_root, certs_dir)
    manifests = validate_profile_set(
        output_root=output_root,
        openssl_binary=openssl_binary,
        ca_cert=ca_cert,
    )
    if device not in manifests:
        raise ProfileError(f"no validated {DEVICES[device].display_name} identity is available")
    passphrase_path = output_root / IDENTITIES_DIR_NAME / device / "client.p12.passphrase"
    passphrase = _load_passphrase(passphrase_path)
    pbcopy_binary = _resolve_pbcopy(pbcopy_binary)
    try:
        result = _run_pbcopy([str(pbcopy_binary)], passphrase.encode("ascii"))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProfileError("pbcopy could not copy the validated passphrase") from exc
    finally:
        del passphrase
    if result.returncode != 0:
        raise ProfileError("pbcopy rejected the validated passphrase")


def _build_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device",
        action="append",
        choices=sorted(DEVICES),
        dest="devices",
        help="Device to issue (repeatable; default: mini and pro)",
    )
    parser.add_argument("--certs-dir", default=str(DEFAULT_CERTS_DIR), help="Owner-only Air PKI directory")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Owner-only profile output directory")
    parser.add_argument("--openssl", default=str(DEFAULT_OPENSSL), help="Absolute OpenSSL executable path")
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Replace selected identities after retaining the complete previous profile set as a local backup",
    )
    return parser


def _run_copy_passphrase(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="export_macos_air_profiles.py copy-passphrase",
        description="Validate a device profile set and copy its PKCS#12 passphrase directly to the macOS clipboard.",
    )
    parser.add_argument("--device", choices=sorted(DEVICES), required=True)
    parser.add_argument("--certs-dir", default=str(DEFAULT_CERTS_DIR), help="Owner-only Air PKI directory")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Owner-only profile output directory")
    parser.add_argument("--openssl", default=str(DEFAULT_OPENSSL), help="Absolute OpenSSL executable path")
    args = parser.parse_args(arguments)
    try:
        copy_passphrase(
            device=args.device,
            certs_dir=Path(args.certs_dir),
            output_root=Path(args.output_root),
            openssl_binary=Path(args.openssl),
        )
    except (OSError, ProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"copied the validated {args.device} PKCS#12 passphrase to the macOS clipboard")
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "copy-passphrase":
        return _run_copy_passphrase(arguments[1:])
    if arguments and arguments[0] == "generate":
        arguments = arguments[1:]
    parser = _build_generate_parser()
    args = parser.parse_args(arguments)
    try:
        result = generate_profiles(
            certs_dir=Path(args.certs_dir),
            output_root=Path(args.output_root),
            openssl_binary=Path(args.openssl),
            devices=tuple(args.devices or ("mini", "pro")),
            rotate=args.rotate,
        )
    except (OSError, ProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.idempotent:
        print(f"validated existing Air profiles; no identities changed: {result.output_root}")
    else:
        print(f"created validated owner-only Air profiles: {result.output_root}")
        print(f"generated identities: {', '.join(result.generated_devices)}")
        if result.preserved_devices:
            print(f"preserved identities: {', '.join(result.preserved_devices)}")
        if result.backup_dir is not None:
            print(f"previous owner-only profile set retained at: {result.backup_dir}")
    for slug in result.selected_devices:
        print(f"{slug} profile: {result.output_root / PROFILES_DIR_NAME / DEVICES[slug].profile_file}")
        print(f"{slug} password file: " f"{result.output_root / IDENTITIES_DIR_NAME / slug / 'client.p12.passphrase'}")
    print("private keys and PKCS#12 passphrases were not printed or embedded as plaintext")
    print("installation: unchanged (no profile, Keychain, WireGuard, or service operations performed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
