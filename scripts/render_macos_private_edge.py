#!/usr/bin/env python3
"""Render an inert, WireGuard-only Caddy edge for a macOS user session.

The renderer consumes the canonical ``services.toml`` registry plus its
owner-only ``services.local.toml`` overlay.  It never creates certificates,
installs files in ``~/Library/LaunchAgents``, or invokes ``launchctl``.

The macOS edge deliberately uses unprivileged HTTPS ports.  A user LaunchAgent
cannot be relied upon to bind TCP 443, and silently rendering such an agent
would create an activation-time failure.  The generated sites use the
WireGuard IPv4 literal, so an iPhone does not need private DNS for first access.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from site_registry import load_services_data, load_sites

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SERVICES_TOML = REPO_ROOT / "services.toml"
DEFAULT_CERTS_DIR = Path.home() / ".config" / "wiring-harness" / "certs"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "config" / "macos-private-edge.local"
DEFAULT_CADDY_BINARY = Path("/opt/homebrew/bin/caddy")
LAUNCHD_LABEL = "dev.user.wiring-harness.macos-private-edge"
MANIFEST_SCHEMA_VERSION = 2
LIVE_SMOKE_QUERY_PARAMETER = "wiring_harness_smoke"
LIVE_SMOKE_LOG_TOKEN_FIELD = "wiring_harness_smoke"
LIVE_SMOKE_LOG_PATH_FIELD = "wiring_harness_path"
ACCESS_LOG_MODE = 0o600
ACCESS_LOG_ROLL_SIZE_MIB = 1
ACCESS_LOG_ROLL_KEEP = 2
ACCESS_LOG_MAX_RECORD_BYTES = 64 * 1024
OPENSSL_COMMANDS = (
    Path("/usr/bin/openssl"),
    Path("/opt/homebrew/bin/openssl"),
    Path("/usr/local/bin/openssl"),
)
SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
SAFE_WIREGUARD_INTERFACE = re.compile(r"utun[0-9]{1,3}\Z")
PLACEHOLDER = re.compile(
    r"(?:<[^>]+>|\$\{|\b(?:change[-_ ]?me|replace[-_ ]?me|todo)\b|example\.(?:com|net|org)|your[-_])",
    re.IGNORECASE,
)
RFC1918_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


@dataclass(frozen=True)
class ReviewedRole:
    owner_repo_name: str
    upstream_port: int
    default_listen_port: int
    health_path: str
    required: bool


@dataclass(frozen=True)
class EdgeService:
    name: str
    role: str
    listen_port: int
    upstream_port: int
    client_ca: Path
    static_root: Path | None = None


REVIEWED_ROLES = {
    "clockwork": ReviewedRole(
        owner_repo_name="clockwork",
        upstream_port=5001,
        default_listen_port=8443,
        health_path="/",
        required=True,
    ),
    "snowbridge": ReviewedRole(
        owner_repo_name="snowbridge",
        upstream_port=8080,
        default_listen_port=8444,
        health_path="/health",
        required=False,
    ),
    "webterm": ReviewedRole(
        owner_repo_name="pit-box",
        upstream_port=7681,
        default_listen_port=8445,
        health_path="/",
        required=False,
    ),
}

SNOWBRIDGE_PROXY_AUTH_HEADER = "X-Snowbridge-Auth-User"
SNOWBRIDGE_PROXY_AUTH_USER = "snowbridge"


class EdgeConfigError(ValueError):
    """The local Air edge configuration is unsafe or incomplete."""


def _local_registry_path(services_path: Path) -> Path:
    return services_path.with_name(services_path.stem + ".local.toml")


def _validate_owner_only_file(path: Path, *, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise EdgeConfigError(f"{description} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EdgeConfigError(f"{description} must be a regular, non-symlink file: {path}")
    if info.st_uid != os.getuid():
        raise EdgeConfigError(f"{description} must be owned by uid {os.getuid()}: {path}")
    if info.st_nlink != 1:
        raise EdgeConfigError(f"{description} must have exactly one hard link: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise EdgeConfigError(f"{description} must be owner-only (chmod 600): {path}")
    _validate_trusted_ancestors(path.parent, description=description)


def _validate_owner_only_directory(path: Path, *, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise EdgeConfigError(f"{description} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EdgeConfigError(f"{description} must be a real directory, not a symlink: {path}")
    if info.st_uid != os.getuid():
        raise EdgeConfigError(f"{description} must be owned by uid {os.getuid()}: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise EdgeConfigError(f"{description} must be owner-only (chmod 700): {path}")
    _validate_trusted_ancestors(path.parent, description=description)


def _validate_trusted_ancestors(path: Path, *, description: str) -> None:
    current = path.resolve(strict=True)
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise EdgeConfigError(f"{description} has a non-directory ancestor: {current}")
        if info.st_uid not in {0, os.getuid()}:
            raise EdgeConfigError(f"{description} has an ancestor owned by another user: {current}")
        permissions = stat.S_IMODE(info.st_mode)
        if permissions & 0o022 and not permissions & stat.S_ISVTX:
            raise EdgeConfigError(f"{description} has a writable untrusted ancestor: {current}")
        if current.parent == current:
            return
        current = current.parent


def _canonical_absolute_path(raw: str | Path, *, description: str) -> Path:
    value = str(raw)
    if any(character.isspace() or ord(character) < 0x20 for character in value):
        raise EdgeConfigError(f"{description} cannot contain whitespace or control characters")
    path = Path(value).expanduser()
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise EdgeConfigError(f"{description} must be an absolute canonical path: {value}")
    return path


def _reject_placeholder(value: object, *, description: str) -> None:
    if isinstance(value, str) and PLACEHOLDER.search(value):
        raise EdgeConfigError(f"{description} contains a placeholder value")


def _parse_wireguard_address(raw: object) -> ipaddress.IPv4Interface:
    if not isinstance(raw, str):
        raise EdgeConfigError("macos_private_edge.wireguard_address must be an IPv4 /32 string")
    _reject_placeholder(raw, description="macos_private_edge.wireguard_address")
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as exc:
        raise EdgeConfigError("macos_private_edge.wireguard_address must be a valid IPv4 /32") from exc
    if not isinstance(interface, ipaddress.IPv4Interface) or interface.network.prefixlen != 32:
        raise EdgeConfigError("macos_private_edge.wireguard_address must be an IPv4 /32")
    if not any(interface.ip in network for network in RFC1918_NETWORKS):
        raise EdgeConfigError("macos_private_edge.wireguard_address must be an RFC1918 WireGuard address")
    return interface


def _parse_wireguard_interface(raw: object) -> str:
    if not isinstance(raw, str) or SAFE_WIREGUARD_INTERFACE.fullmatch(raw) is None:
        raise EdgeConfigError("macos_private_edge.wireguard_interface must match utun<number>")
    return raw


def _interface_ipv4_addresses(interface: str) -> set[ipaddress.IPv4Address]:
    commands: tuple[tuple[str, ...], ...] = (
        ("/sbin/ifconfig", interface),
        ("/usr/sbin/ifconfig", interface),
        ("/usr/sbin/ip", "-4", "-o", "address", "show", "dev", interface),
        ("/sbin/ip", "-4", "-o", "address", "show", "dev", interface),
    )
    attempted = False
    for command in commands:
        if not Path(command[0]).is_file() or not os.access(command[0], os.X_OK):
            continue
        attempted = True
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0:
            continue
        addresses: set[ipaddress.IPv4Address] = set()
        for raw in re.findall(r"\binet\s+(\d+(?:\.\d+){3})(?:/\d+)?\b", result.stdout):
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if isinstance(parsed, ipaddress.IPv4Address):
                addresses.add(parsed)
        return addresses
    if attempted:
        raise EdgeConfigError(f"configured WireGuard interface is unavailable: {interface}")
    raise EdgeConfigError("cannot inspect the WireGuard interface: no trusted ifconfig/ip executable")


def _verify_wireguard_assignment(interface: str, address: ipaddress.IPv4Address) -> None:
    addresses = _interface_ipv4_addresses(interface)
    if address not in addresses:
        raise EdgeConfigError(f"WireGuard address {address} is not assigned to interface {interface}")


def _positive_port(raw: object, *, description: str) -> int:
    if isinstance(raw, bool):
        raise EdgeConfigError(f"{description} must be an integer")
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise EdgeConfigError(f"{description} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise EdgeConfigError(f"{description} must be between 1 and 65535")
    return port


def _validate_cert_file(path: Path, *, description: str) -> None:
    _validate_owner_only_file(path, description=description)
    try:
        text = path.read_text()
    except UnicodeDecodeError as exc:
        raise EdgeConfigError(f"{description} must be a PEM certificate: {path}") from exc
    if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
        raise EdgeConfigError(f"{description} must be a PEM certificate: {path}")


def _validate_private_key_file(path: Path, *, description: str) -> None:
    _validate_owner_only_file(path, description=description)
    try:
        text = path.read_text()
    except UnicodeDecodeError as exc:
        raise EdgeConfigError(f"{description} must be a PEM private key: {path}") from exc
    private_key_label = "PRIVATE" + " KEY"
    accepted_headers = tuple(f"-----BEGIN {prefix}{private_key_label}-----" for prefix in ("", "RSA ", "EC "))
    if not any(header in text for header in accepted_headers) or "-----END " not in text:
        raise EdgeConfigError(f"{description} must be an unencrypted PEM private key: {path}")
    if PLACEHOLDER.search(text):
        raise EdgeConfigError(f"{description} contains a placeholder value")


def _decode_certificate(path: Path) -> dict:
    try:
        return ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise EdgeConfigError(f"unable to decode server certificate: {path}") from exc


def _validate_server_ip_san(server_cert: Path, wireguard_ip: ipaddress.IPv4Address) -> None:
    decoded = _decode_certificate(server_cert)
    sans = decoded.get("subjectAltName", ())
    ip_sans = set()
    for kind, value in sans:
        if kind != "IP Address":
            continue
        try:
            ip_sans.add(ipaddress.ip_address(value))
        except ValueError:
            continue
    if wireguard_ip not in ip_sans:
        raise EdgeConfigError(f"server certificate must contain IP SAN {wireguard_ip}")


def _validate_cert_material(
    certs_dir: Path,
    services: list[EdgeService],
    wireguard_ip: ipaddress.IPv4Address,
) -> tuple[Path, Path]:
    _validate_owner_only_directory(certs_dir, description="certificate directory")
    server_cert = certs_dir / "server.crt"
    server_key = certs_dir / "server.key"
    shared_ca = certs_dir / "ca.crt"
    _validate_cert_file(server_cert, description="server certificate")
    _validate_private_key_file(server_key, description="server private key")
    _validate_cert_file(shared_ca, description="shared client CA")
    _validate_server_ip_san(server_cert, wireguard_ip)
    for service in services:
        if service.client_ca == shared_ca:
            continue
        _validate_owner_only_directory(service.client_ca.parent, description=f"{service.role} client CA directory")
        _validate_cert_file(service.client_ca, description=f"{service.role} client CA")
    return server_cert, server_key


def _edge_section(data: dict) -> dict:
    edge = data.get("macos_private_edge")
    if not isinstance(edge, dict):
        raise EdgeConfigError("services.local.toml must define [macos_private_edge]")
    expected = {"wireguard_address", "wireguard_interface"}
    unknown = set(edge) - expected
    missing = expected - set(edge)
    if unknown:
        raise EdgeConfigError(f"unsupported [macos_private_edge] fields: {', '.join(sorted(unknown))}")
    if missing:
        raise EdgeConfigError(f"missing [macos_private_edge] fields: {', '.join(sorted(missing))}")
    return edge


def _select_services(sites: list[dict], certs_dir: Path) -> list[EdgeService]:
    selected: list[EdgeService] = []
    seen_roles: set[str] = set()
    seen_ports: set[int] = set()
    for site in sites:
        role_raw = site.get("macos_edge_role")
        if role_raw is None:
            if "macos_edge_listen_port" in site:
                raise EdgeConfigError(f"{site.get('name', '<unnamed>')}: listen port requires macos_edge_role")
            continue
        if not isinstance(role_raw, str) or role_raw not in REVIEWED_ROLES:
            raise EdgeConfigError(f"{site.get('name', '<unnamed>')}: unsupported macOS edge role {role_raw!r}")
        role = role_raw
        spec = REVIEWED_ROLES[role]
        if role in seen_roles:
            raise EdgeConfigError(f"macOS edge role {role!r} may appear only once")

        name = site.get("name")
        if not isinstance(name, str) or SAFE_NAME.fullmatch(name) is None:
            raise EdgeConfigError(f"{role}: service name must use lowercase registry-safe characters")
        for field in ("name", "hostname", "owner_repo", "client_ca_path"):
            if field in site:
                _reject_placeholder(site[field], description=f"{name}.{field}")
        if site.get("owner_repo") and Path(str(site["owner_repo"])).name != spec.owner_repo_name:
            raise EdgeConfigError(f"{name}: owner_repo must resolve to the reviewed {spec.owner_repo_name!r} repo")
        if not site.get("owner_repo"):
            raise EdgeConfigError(f"{name}: owner_repo is required for the macOS edge")
        if site.get("ingress") != "wiring-harness-caddy":
            raise EdgeConfigError(f"{name}: ingress must be wiring-harness-caddy")
        if site.get("access_mode") not in {"shared-mtls", "snowbridge-mtls"}:
            raise EdgeConfigError(f"{name}: access_mode must require mTLS")
        if "unix_socket" in site or any(
            field in site for field in ("port_env_key", "port_default", "env_file", "proxy_headers")
        ):
            raise EdgeConfigError(f"{name}: macOS edge requires one reviewed explicit loopback TCP port")
        upstream_port = _positive_port(site.get("port"), description=f"{name}.port")
        if upstream_port != spec.upstream_port:
            raise EdgeConfigError(f"{name}: {role} upstream must be 127.0.0.1:{spec.upstream_port}")

        listen_port = _positive_port(
            site.get("macos_edge_listen_port", spec.default_listen_port),
            description=f"{name}.macos_edge_listen_port",
        )
        if listen_port != spec.default_listen_port:
            raise EdgeConfigError(f"{name}: {role} macOS edge must use the reviewed port {spec.default_listen_port}")
        if listen_port in seen_ports:
            raise EdgeConfigError(f"{name}: macOS edge listen ports must be unique")

        ca_raw = site.get("client_ca_path")
        client_ca = (
            _canonical_absolute_path(ca_raw, description=f"{name}.client_ca_path") if ca_raw else certs_dir / "ca.crt"
        )
        static_root = None
        if role == "webterm":
            static_root = Path(str(site["owner_repo"])).expanduser().resolve() / "build" / "macos-webterm"
            if any(character.isspace() or ord(character) < 0x20 for character in str(static_root)):
                raise EdgeConfigError(f"{name}: Webterm static root cannot contain whitespace or control characters")
        selected.append(
            EdgeService(
                name=name,
                role=role,
                listen_port=listen_port,
                upstream_port=upstream_port,
                client_ca=client_ca,
                static_root=static_root,
            )
        )
        seen_roles.add(role)
        seen_ports.add(listen_port)

    missing = [role for role, spec in REVIEWED_ROLES.items() if spec.required and role not in seen_roles]
    if missing:
        raise EdgeConfigError(f"missing required macOS edge role(s): {', '.join(missing)}")
    return sorted(selected, key=lambda service: service.listen_port)


def generate_caddyfile(
    wireguard_ip: ipaddress.IPv4Address,
    services: list[EdgeService],
    server_cert: Path,
    server_key: Path,
    logs_dir: Path,
) -> str:
    def webterm_routes(service: EdgeService) -> str:
        if service.static_root is None:
            raise EdgeConfigError("webterm requires a static root")
        return (
            "\t@api path /api/*\n"
            "\thandle @api {\n"
            "\t\treverse_proxy 127.0.0.1:7682\n"
            "\t}\n\n"
            "\t@term_ttyd path /term/token /term/ws\n"
            "\thandle @term_ttyd {\n"
            "\t\turi strip_prefix /term\n"
            f"\t\treverse_proxy 127.0.0.1:{service.upstream_port}\n"
            "\t}\n\n"
            "\t@home path /\n"
            "\thandle @home {\n"
            "\t\theader Cache-Control \"no-store\"\n"
            f"\t\troot * {service.static_root}\n"
            "\t\trewrite * /home.html\n"
            "\t\tfile_server\n"
            "\t}\n\n"
            "\t@term_slash path /term/\n"
            "\thandle @term_slash {\n"
            "\t\tredir * /term 308\n"
            "\t}\n\n"
            "\t@term path /term\n"
            "\thandle @term {\n"
            "\t\theader Cache-Control \"no-store\"\n"
            f"\t\troot * {service.static_root}\n"
            "\t\trewrite * /index.html\n"
            "\t\tfile_server\n"
            "\t}\n\n"
            "\thandle {\n"
            f"\t\treverse_proxy 127.0.0.1:{service.upstream_port}\n"
            "\t}\n"
        )

    blocks: list[str] = []
    for service in services:
        access_log = _access_log_path(logs_dir, service)
        health_path = REVIEWED_ROLES[service.role].health_path
        probe_expression = (
            f"method('GET') && path('{health_path}') && "
            f"{{query.{LIVE_SMOKE_QUERY_PARAMETER}}}.matches('^[A-Za-z0-9_-]{{16,128}}$')"
        )
        if service.role == "webterm":
            reverse_proxy = webterm_routes(service)
        elif service.role == "snowbridge":
            reverse_proxy = (
                f"\treverse_proxy 127.0.0.1:{service.upstream_port} {{\n"
                f'\t\theader_up {SNOWBRIDGE_PROXY_AUTH_HEADER} "{SNOWBRIDGE_PROXY_AUTH_USER}"\n'
                "\t}\n"
            )
        else:
            reverse_proxy = f"\treverse_proxy 127.0.0.1:{service.upstream_port}\n"
        blocks.append(
            f"# Reviewed {service.role} edge\n"
            f"https://{wireguard_ip}:{service.listen_port} {{\n"
            f"\tbind {wireguard_ip}\n"
            f"\ttls {server_cert} {server_key} {{\n"
            "\t\tclient_auth {\n"
            "\t\t\tmode require_and_verify\n"
            f"\t\t\ttrust_pool file {service.client_ca}\n"
            "\t\t}\n"
            "\t}\n"
            "\n"
            f"\t@wiringHarnessSmoke `{probe_expression}`\n"
            f"\t@notWiringHarnessSmoke `!({probe_expression})`\n"
            f"\tlog_append @wiringHarnessSmoke {LIVE_SMOKE_LOG_TOKEN_FIELD} "
            f"{{query.{LIVE_SMOKE_QUERY_PARAMETER}}}\n"
            f"\tlog_append @wiringHarnessSmoke {LIVE_SMOKE_LOG_PATH_FIELD} {{path}}\n"
            "\tlog_skip @notWiringHarnessSmoke\n"
            "\tlog {\n"
            f"\t\toutput file {access_log} {{\n"
            f"\t\t\tmode {ACCESS_LOG_MODE:04o}\n"
            f"\t\t\troll_size {ACCESS_LOG_ROLL_SIZE_MIB}MiB\n"
            f"\t\t\troll_keep {ACCESS_LOG_ROLL_KEEP}\n"
            "\t\t}\n"
            "\t\tformat filter {\n"
            "\t\t\trequest>uri delete\n"
            "\t\t\trequest>remote_port delete\n"
            "\t\t\trequest>client_ip delete\n"
            "\t\t\trequest>proto delete\n"
            "\t\t\trequest>headers delete\n"
            "\t\t\trequest>tls delete\n"
            "\t\t\tresp_headers delete\n"
            "\t\t\tuser_id delete\n"
            "\t\t\twrap json\n"
            "\t\t}\n"
            "\t}\n"
            "\n"
            "\tencode zstd gzip\n"
            f"{reverse_proxy}"
            "\n"
            "\theader {\n"
            '\t\tX-Content-Type-Options "nosniff"\n'
            '\t\tX-Frame-Options "SAMEORIGIN"\n'
            '\t\tReferrer-Policy "no-referrer"\n'
            "\t}\n"
            "}"
        )
    local_webterm = next((service for service in services if service.role == "webterm"), None)
    local_block = ""
    if local_webterm is not None:
        local_block = (
            "\n\n# Air-local Webterm home page; loopback only, never LAN or WAN.\n"
            "http://127.0.0.1:7680 {\n"
            "\tbind 127.0.0.1\n"
            f"{webterm_routes(local_webterm)}"
            "\theader {\n"
            '\t\tX-Content-Type-Options "nosniff"\n'
            '\t\tX-Frame-Options "SAMEORIGIN"\n'
            '\t\tReferrer-Policy "no-referrer"\n'
            "\t}\n"
            "}\n"
        )
    return (
        "{\n"
        "\tadmin off\n"
        "\tauto_https disable_redirects\n"
        "\tskip_install_trust\n"
        f"\t# Select the protected TLS policy when an IP-literal client omits SNI.\n"
        f"\tdefault_sni {wireguard_ip}\n"
        "\tservers {\n"
        "\t\t# The original ClientHello still has empty SNI, so its HTTP Host\n"
        "\t\t# cannot equal it. Every site on this exact bind requires mTLS.\n"
        "\t\tstrict_sni_host insecure_off\n"
        "\t}\n"
        "}\n\n"
        "# Render-only macOS private edge; no wildcard listener or DNS dependency.\n\n" + "\n\n".join(blocks) + "\n" + local_block
    )


def generate_launch_agent(caddy_binary: Path, caddyfile: Path, logs_dir: Path) -> bytes:
    payload = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [
            str(caddy_binary),
            "run",
            "--config",
            str(caddyfile),
            "--adapter",
            "caddyfile",
        ],
        "WorkingDirectory": str(caddyfile.parent),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
        "ThrottleInterval": 15,
        "Umask": 0o077,
        "StandardOutPath": str(logs_dir / "caddy.stdout.log"),
        "StandardErrorPath": str(logs_dir / "caddy.stderr.log"),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def _validate_existing_output(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EdgeConfigError(f"existing output must be a regular, non-symlink file: {path}")
    if info.st_uid != os.getuid():
        raise EdgeConfigError(f"existing output must be owned by uid {os.getuid()}: {path}")
    if info.st_nlink != 1:
        raise EdgeConfigError(f"existing output must have exactly one hard link: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise EdgeConfigError(f"existing output must remain owner-only: {path}")


def _safe_write(path: Path, content: str | bytes) -> None:
    _validate_owner_only_directory(path.parent, description="output directory")
    _validate_existing_output(path)
    if isinstance(content, str):
        content = content.encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    replaced = False
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise EdgeConfigError(f"unsafe temporary output file: {temporary}")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _validate_existing_output(path)
        os.replace(temporary, path)
        replaced = True
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            temporary.unlink(missing_ok=True)


def _access_log_path(logs_dir: Path, service: EdgeService) -> Path:
    return logs_dir / f"{service.role}.access.json"


def _ensure_owner_only_access_log(path: Path) -> None:
    """Create an empty access log without truncating an existing live log."""

    _validate_owner_only_directory(path.parent, description="access log directory")
    try:
        info = path.lstat()
    except FileNotFoundError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, ACCESS_LOG_MODE)
        except FileExistsError:
            info = path.lstat()
        else:
            try:
                os.fchmod(descriptor, ACCESS_LOG_MODE)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise EdgeConfigError(f"unsafe access log file: {path}")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EdgeConfigError(f"access log must be a regular, non-symlink file: {path}")
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        raise EdgeConfigError(f"access log must be singly linked and owned by uid {os.getuid()}: {path}")
    if stat.S_IMODE(info.st_mode) != ACCESS_LOG_MODE:
        raise EdgeConfigError(f"access log must have mode 0600: {path}")


def _validate_access_log_set(path: Path) -> None:
    """Validate one current probe log and its bounded Caddy roll set."""

    _validate_owner_only_directory(path.parent, description="access log directory")
    directory_mode = stat.S_IMODE(path.parent.lstat().st_mode)
    if directory_mode != 0o700:
        raise EdgeConfigError(f"access log directory must have mode 0700: {path.parent}")
    _validate_owner_only_file(path, description="access log")
    if stat.S_IMODE(path.lstat().st_mode) != ACCESS_LOG_MODE:
        raise EdgeConfigError(f"access log must have mode 0600: {path}")

    suffix = re.escape(path.suffix)
    rolled_pattern = re.compile(
        rf"{re.escape(path.stem)}-\d{{4}}-\d{{2}}-\d{{2}}T[^/]+-(?:size|time){suffix}(?:\.gz)?\Z"
    )
    rolled: list[Path] = []
    for candidate in path.parent.iterdir():
        if candidate.name == path.name or not candidate.name.startswith(path.stem):
            continue
        if rolled_pattern.fullmatch(candidate.name) is None:
            raise EdgeConfigError(f"unrecognized access log roll file: {candidate}")
        _validate_owner_only_file(candidate, description="rolled access log")
        if stat.S_IMODE(candidate.lstat().st_mode) != ACCESS_LOG_MODE:
            raise EdgeConfigError(f"rolled access log must have mode 0600: {candidate}")
        rolled.append(candidate)

    if len(rolled) > ACCESS_LOG_ROLL_KEEP:
        raise EdgeConfigError(f"access log exceeds the reviewed roll count: {path}")
    maximum_size = ACCESS_LOG_ROLL_SIZE_MIB * 1024 * 1024 + ACCESS_LOG_MAX_RECORD_BYTES
    for candidate in (path, *rolled):
        if candidate.lstat().st_size > maximum_size:
            raise EdgeConfigError(f"access log exceeds the reviewed size bound: {candidate}")


def _client_trust_topology(services: list[EdgeService]) -> str:
    return _client_trust_topology_for_paths([service.client_ca for service in services])


def _openssl_binary() -> Path:
    for candidate in OPENSSL_COMMANDS:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise EdgeConfigError("cannot inspect client CA authorities: no trusted OpenSSL executable")


def _certificate_trust_authority(block: str, *, path: Path) -> bytes:
    """Return a stable subject-and-SPKI identity for one trust anchor."""

    try:
        result = subprocess.run(
            [str(_openssl_binary()), "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-pubkey"],
            input=block,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EdgeConfigError(f"cannot inspect client CA authority: {path}") from exc
    marker = "-----BEGIN PUBLIC KEY-----"
    if result.returncode != 0 or marker not in result.stdout or "-----END PUBLIC KEY-----" not in result.stdout:
        raise EdgeConfigError(f"client CA bundle contains an invalid certificate: {path}")
    subject, public_key = result.stdout.split(marker, 1)
    subject = subject.removeprefix("subject=").strip()
    public_key = marker + public_key
    if not subject:
        raise EdgeConfigError(f"client CA certificate has no subject: {path}")
    normalized_public_key = "".join(public_key.split())
    return hashlib.sha256(f"{subject}\0{normalized_public_key}".encode()).digest()


def _client_trust_authorities(path: Path) -> frozenset[bytes]:
    text = path.read_text()
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
        text,
        flags=re.DOTALL,
    )
    if not blocks:
        raise EdgeConfigError(f"client CA bundle contains no certificates: {path}")
    authorities: set[bytes] = set()
    for block in blocks:
        authorities.add(_certificate_trust_authority(block, path=path))
    return frozenset(authorities)


def _client_trust_topology_for_paths(paths: Sequence[Path]) -> str:
    trust_sets = [_client_trust_authorities(path) for path in paths]
    if len(trust_sets) == 1:
        return "single"
    if all(item == trust_sets[0] for item in trust_sets[1:]):
        return "shared"
    if set.intersection(*(set(item) for item in trust_sets)):
        return "overlapping"
    return "distinct"


def render_bundle(
    *,
    services_path: Path,
    certs_dir: Path,
    output_dir: Path,
    caddy_binary: Path,
    validate_caddy: bool = False,
) -> dict:
    services_path = _canonical_absolute_path(services_path, description="services registry path")
    certs_dir = _canonical_absolute_path(certs_dir, description="certificate directory")
    output_dir = _canonical_absolute_path(output_dir, description="output directory")
    caddy_binary = _canonical_absolute_path(caddy_binary, description="Caddy binary path")

    local_registry = _local_registry_path(services_path)
    _validate_owner_only_file(local_registry, description="local services registry")
    data = load_services_data(services_path)
    edge = _edge_section(data)
    wireguard_interface = _parse_wireguard_interface(edge.get("wireguard_interface"))
    wireguard = _parse_wireguard_address(edge.get("wireguard_address"))
    _verify_wireguard_assignment(wireguard_interface, wireguard.ip)
    services = _select_services(load_sites(services_path), certs_dir)
    server_cert, server_key = _validate_cert_material(certs_dir, services, wireguard.ip)

    output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    _validate_owner_only_directory(output_dir, description="output directory")
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(mode=0o700, exist_ok=True)
    _validate_owner_only_directory(logs_dir, description="log output directory")
    for service in services:
        _ensure_owner_only_access_log(_access_log_path(logs_dir, service))
        _validate_access_log_set(_access_log_path(logs_dir, service))

    caddyfile = output_dir / "Caddyfile"
    plist_path = output_dir / f"{LAUNCHD_LABEL}.plist"
    manifest_path = output_dir / "manifest.json"
    _safe_write(caddyfile, generate_caddyfile(wireguard.ip, services, server_cert, server_key, logs_dir))
    _safe_write(plist_path, generate_launch_agent(caddy_binary, caddyfile, logs_dir))

    caddy_installed = caddy_binary.is_file() and os.access(caddy_binary, os.X_OK)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "activation": "render-only",
        "wireguard_interface": wireguard_interface,
        "wireguard_bind": str(wireguard),
        "uses_private_dns": False,
        "server_certificate_required_ip_san": str(wireguard.ip),
        "client_auth": "require_and_verify",
        "default_sni": str(wireguard.ip),
        "strict_sni_host": "insecure_off-after-default-sni",
        "client_trust_topology": _client_trust_topology(services),
        "tls": {
            "server_certificate": str(server_cert),
            "server_private_key": str(server_key),
        },
        "launchd": {
            "scope": "user",
            "label": LAUNCHD_LABEL,
            "rendered_plist": str(plist_path),
            "install_target": str(Path.home() / "Library" / "LaunchAgents" / plist_path.name),
            "privileged_ports_allowed": False,
        },
        "caddy": {
            "binary": str(caddy_binary),
            "installed": caddy_installed,
            "config": str(caddyfile),
            "admin_api": "off",
            "automatic_http_redirects": "off",
        },
        "services": [
            {
                "registry_name": service.name,
                "role": service.role,
                "url": f"https://{wireguard.ip}:{service.listen_port}/",
                "upstream": f"http://127.0.0.1:{service.upstream_port}",
                "client_ca": str(service.client_ca),
                "static_root": str(service.static_root) if service.static_root is not None else None,
                "access_log": {
                    "path": str(_access_log_path(logs_dir, service)),
                    "scope": "live-smoke-query-only",
                    "format": "json",
                    "query_parameter": LIVE_SMOKE_QUERY_PARAMETER,
                    "query_value_filter": "opaque-non-secret",
                    "request_uri": "deleted",
                    "probe_token_field": LIVE_SMOKE_LOG_TOKEN_FIELD,
                    "probe_path_field": LIVE_SMOKE_LOG_PATH_FIELD,
                    "mode": f"{ACCESS_LOG_MODE:04o}",
                    "roll_size_mib": ACCESS_LOG_ROLL_SIZE_MIB,
                    "roll_keep": ACCESS_LOG_ROLL_KEEP,
                },
                "proxy_auth_header_override": (
                    {
                        "header": SNOWBRIDGE_PROXY_AUTH_HEADER,
                        "value": SNOWBRIDGE_PROXY_AUTH_USER,
                    }
                    if service.role == "snowbridge"
                    else None
                ),
            }
            for service in services
        ],
    }
    _safe_write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if validate_caddy:
        if not caddy_installed:
            raise EdgeConfigError(f"Caddy is not installed or executable: {caddy_binary}")
        try:
            result = subprocess.run(
                [str(caddy_binary), "validate", "--config", str(caddyfile), "--adapter", "caddyfile"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise EdgeConfigError("caddy validate timed out after 30 seconds") from exc
        if result.returncode != 0:
            detail = (result.stdout + result.stderr).strip()
            raise EdgeConfigError(f"caddy validate failed: {detail}")
        manifest["caddy"]["validated"] = True
        _safe_write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    else:
        manifest["caddy"]["validated"] = False
        _safe_write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services", default=str(DEFAULT_SERVICES_TOML), help="Base services.toml path")
    parser.add_argument("--certs-dir", default=str(DEFAULT_CERTS_DIR), help="Owner-only local certificate directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Owner-only render output directory")
    parser.add_argument("--caddy-binary", default=str(DEFAULT_CADDY_BINARY), help="Expected Caddy executable path")
    parser.add_argument("--validate-caddy", action="store_true", help="Also invoke caddy validate; never activates it")
    args = parser.parse_args(argv)
    try:
        manifest = render_bundle(
            services_path=Path(args.services).expanduser().absolute(),
            certs_dir=Path(args.certs_dir).expanduser().absolute(),
            output_dir=Path(args.output_dir).expanduser().absolute(),
            caddy_binary=Path(args.caddy_binary).expanduser().absolute(),
            validate_caddy=args.validate_caddy,
        )
    except (EdgeConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"rendered owner-only macOS edge: {args.output_dir}")
    for service in manifest["services"]:
        print(f"  {service['role']}: {service['url']} -> {service['upstream']}")
    print("activation: render-only (no launchctl or Caddy process changes made)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
