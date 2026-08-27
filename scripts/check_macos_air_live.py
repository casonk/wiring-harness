#!/usr/bin/env python3
"""Read-only readiness and peer-driven smoke checks for the macOS Air edge.

The Air host cannot reliably connect to its own point-to-point WireGuard /32:
macOS routes that destination back into the utun interface.  This checker
therefore probes only loopback backends from Air.  Its end-to-end mode waits
for narrowly filtered Caddy access records produced by an independent mesh
peer; it never sends a request to the Air WireGuard address itself.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import render_macos_private_edge as edge

DEFAULT_MANIFEST = edge.DEFAULT_OUTPUT_DIR / "manifest.json"
MAX_TIMEOUT_SECONDS = 600.0
POLL_INTERVAL_SECONDS = 0.2
PEER_ROUTE_COMMANDS = (Path("/sbin/route"), Path("/usr/sbin/route"))
LAUNCHCTL_COMMAND = Path("/bin/launchctl")
LSOF_COMMANDS = (Path("/usr/sbin/lsof"), Path("/usr/bin/lsof"))
PS_COMMANDS = (Path("/bin/ps"), Path("/usr/bin/ps"))


class LiveCheckError(RuntimeError):
    """The rendered or live edge does not satisfy its reviewed contract."""


@dataclass(frozen=True)
class ServiceProbe:
    registry_name: str
    role: str
    url: str
    listen_port: int
    upstream_port: int
    health_path: str
    client_ca: Path
    access_log: Path
    query_parameter: str
    probe_token_field: str
    probe_path_field: str
    static_root: Path | None = None


@dataclass(frozen=True)
class LiveManifest:
    path: Path
    wireguard_interface: str
    wireguard: ipaddress.IPv4Interface
    caddy_binary: Path
    caddy_config: Path
    launchd_label: str
    rendered_plist: Path
    installed_plist: Path
    server_certificate: Path
    server_private_key: Path
    trust_topology: str
    services: tuple[ServiceProbe, ...]


@dataclass
class LogCursor:
    path: Path
    device: int
    inode: int
    offset: int
    partial: bytes = b""


CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
BackendProbe = Callable[[ServiceProbe], int]


def _run_command(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise LiveCheckError(f"command timed out: {command[0]}") from exc
    except OSError as exc:
        raise LiveCheckError(f"cannot execute required command: {command[0]}") from exc


def _canonical_path(raw: object, *, description: str) -> Path:
    if not isinstance(raw, str):
        raise LiveCheckError(f"{description} must be an absolute canonical path")
    try:
        return edge._canonical_absolute_path(raw, description=description)
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc


def _owner_only_file(path: Path, *, description: str, exact_mode: int = 0o600) -> None:
    try:
        edge._validate_owner_only_file(path, description=description)
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc
    mode = stat.S_IMODE(path.lstat().st_mode)
    if mode != exact_mode:
        raise LiveCheckError(f"{description} must have mode {exact_mode:04o}: {path}")


def _required_mapping(value: object, *, description: str) -> dict:
    if not isinstance(value, dict):
        raise LiveCheckError(f"{description} must be an object")
    return value


def _parse_service(raw: object, *, manifest_dir: Path, wireguard_ip: ipaddress.IPv4Address) -> ServiceProbe:
    service = _required_mapping(raw, description="manifest service")
    registry_name = service.get("registry_name")
    if not isinstance(registry_name, str) or edge.SAFE_NAME.fullmatch(registry_name) is None:
        raise LiveCheckError("manifest contains an invalid service registry name")
    role = service.get("role")
    if not isinstance(role, str) or role not in edge.REVIEWED_ROLES:
        raise LiveCheckError(f"manifest contains an unsupported service role: {role!r}")

    url = service.get("url")
    if not isinstance(url, str):
        raise LiveCheckError(f"{role}: URL must be a string")
    try:
        parsed_url = urllib.parse.urlsplit(url)
        url_port = parsed_url.port
    except ValueError as exc:
        raise LiveCheckError(f"{role}: malformed edge URL") from exc
    expected_listen_port = edge.REVIEWED_ROLES[role].default_listen_port
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != str(wireguard_ip)
        or url_port != expected_listen_port
        or parsed_url.path != "/"
        or parsed_url.query
        or parsed_url.fragment
        or parsed_url.username is not None
    ):
        raise LiveCheckError(f"{role}: edge URL is outside the reviewed WireGuard endpoint")

    upstream = service.get("upstream")
    if not isinstance(upstream, str):
        raise LiveCheckError(f"{role}: upstream must be a string")
    try:
        parsed_upstream = urllib.parse.urlsplit(upstream)
        upstream_port = parsed_upstream.port
    except ValueError as exc:
        raise LiveCheckError(f"{role}: malformed upstream") from exc
    expected_upstream_port = edge.REVIEWED_ROLES[role].upstream_port
    if (
        parsed_upstream.scheme != "http"
        or parsed_upstream.hostname != "127.0.0.1"
        or upstream_port != expected_upstream_port
        or parsed_upstream.path not in {"", "/"}
        or parsed_upstream.query
        or parsed_upstream.fragment
        or parsed_upstream.username is not None
    ):
        raise LiveCheckError(f"{role}: upstream is outside the reviewed loopback endpoint")

    client_ca = _canonical_path(service.get("client_ca"), description=f"{role} client CA path")
    try:
        edge._validate_cert_file(client_ca, description=f"{role} client CA")
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc

    static_root = None
    if role == "webterm":
        static_root = _canonical_path(service.get("static_root"), description="webterm static root")

    access = _required_mapping(service.get("access_log"), description=f"{role} access log")
    access_log = _canonical_path(access.get("path"), description=f"{role} access log path")
    expected_log = manifest_dir / "logs" / f"{role}.access.json"
    if access_log != expected_log:
        raise LiveCheckError(f"{role}: access log must remain inside the rendered owner-only log directory")
    expected_access = {
        "scope": "live-smoke-query-only",
        "format": "json",
        "query_parameter": edge.LIVE_SMOKE_QUERY_PARAMETER,
        "query_value_filter": "opaque-non-secret",
        "request_uri": "deleted",
        "probe_token_field": edge.LIVE_SMOKE_LOG_TOKEN_FIELD,
        "probe_path_field": edge.LIVE_SMOKE_LOG_PATH_FIELD,
        "mode": f"{edge.ACCESS_LOG_MODE:04o}",
        "roll_size_mib": edge.ACCESS_LOG_ROLL_SIZE_MIB,
        "roll_keep": edge.ACCESS_LOG_ROLL_KEEP,
    }
    for field, expected in expected_access.items():
        if access.get(field) != expected:
            raise LiveCheckError(f"{role}: unsupported access-log {field}")
    try:
        edge._validate_access_log_set(access_log)
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc

    return ServiceProbe(
        registry_name=registry_name,
        role=role,
        url=url,
        listen_port=expected_listen_port,
        upstream_port=upstream_port,
        health_path=edge.REVIEWED_ROLES[role].health_path,
        client_ca=client_ca,
        access_log=access_log,
        query_parameter=edge.LIVE_SMOKE_QUERY_PARAMETER,
        probe_token_field=edge.LIVE_SMOKE_LOG_TOKEN_FIELD,
        probe_path_field=edge.LIVE_SMOKE_LOG_PATH_FIELD,
        static_root=static_root,
    )


def load_manifest(path: Path) -> LiveManifest:
    path = path.expanduser().absolute()
    _owner_only_file(path, description="macOS Air live manifest")
    try:
        raw = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveCheckError(f"cannot decode macOS Air live manifest: {path}") from exc
    manifest = _required_mapping(raw, description="macOS Air live manifest")
    if manifest.get("schema_version") != edge.MANIFEST_SCHEMA_VERSION:
        raise LiveCheckError("rerender the macOS Air edge before running the live checker")
    expected_policy = {
        "activation": "render-only",
        "uses_private_dns": False,
        "client_auth": "require_and_verify",
        "strict_sni_host": "insecure_off-after-default-sni",
    }
    for field, expected in expected_policy.items():
        if manifest.get(field) != expected:
            raise LiveCheckError(f"manifest has unsupported {field!r} policy")

    try:
        wireguard = edge._parse_wireguard_address(manifest.get("wireguard_bind"))
        wireguard_interface = edge._parse_wireguard_interface(manifest.get("wireguard_interface"))
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc
    if manifest.get("server_certificate_required_ip_san") != str(wireguard.ip):
        raise LiveCheckError("manifest server IP-SAN requirement does not match its WireGuard bind")

    caddy = _required_mapping(manifest.get("caddy"), description="manifest Caddy state")
    caddy_binary = _canonical_path(caddy.get("binary"), description="Caddy binary path")
    caddy_config = _canonical_path(caddy.get("config"), description="Caddy config path")
    if caddy_config != path.parent / "Caddyfile":
        raise LiveCheckError("Caddy config must remain beside the rendered manifest")
    if not caddy_binary.is_file() or not os.access(caddy_binary, os.X_OK):
        raise LiveCheckError(f"Caddy binary is missing or not executable: {caddy_binary}")
    _owner_only_file(caddy_config, description="rendered Caddy config")
    if caddy.get("admin_api") != "off" or caddy.get("automatic_http_redirects") != "off":
        raise LiveCheckError("rendered Caddy policy unexpectedly enables an admin or redirect surface")

    launchd = _required_mapping(manifest.get("launchd"), description="manifest launchd state")
    if launchd.get("scope") != "user" or launchd.get("privileged_ports_allowed") is not False:
        raise LiveCheckError("manifest launchd policy is outside the reviewed user boundary")
    launchd_label = launchd.get("label")
    if launchd_label != edge.LAUNCHD_LABEL:
        raise LiveCheckError("manifest contains an unexpected LaunchAgent label")
    rendered_plist = _canonical_path(launchd.get("rendered_plist"), description="rendered LaunchAgent path")
    installed_plist = _canonical_path(launchd.get("install_target"), description="installed LaunchAgent path")
    if rendered_plist != path.parent / f"{edge.LAUNCHD_LABEL}.plist":
        raise LiveCheckError("rendered LaunchAgent must remain beside the manifest")
    _owner_only_file(rendered_plist, description="rendered LaunchAgent")
    _owner_only_file(installed_plist, description="installed LaunchAgent")

    tls = _required_mapping(manifest.get("tls"), description="manifest TLS state")
    server_certificate = _canonical_path(tls.get("server_certificate"), description="server certificate path")
    server_private_key = _canonical_path(tls.get("server_private_key"), description="server private key path")
    try:
        edge._validate_cert_file(server_certificate, description="server certificate")
        edge._validate_private_key_file(server_private_key, description="server private key")
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc

    services_raw = manifest.get("services")
    if not isinstance(services_raw, list) or not services_raw:
        raise LiveCheckError("manifest must contain at least one reviewed service")
    services = tuple(_parse_service(item, manifest_dir=path.parent, wireguard_ip=wireguard.ip) for item in services_raw)
    roles = [service.role for service in services]
    if len(roles) != len(set(roles)) or "clockwork" not in roles:
        raise LiveCheckError("manifest service roles are duplicate or missing required Clockwork")

    topology = _trust_topology(services)
    if manifest.get("client_trust_topology") != topology:
        raise LiveCheckError("manifest client-trust topology has drifted from its CA files")
    return LiveManifest(
        path=path,
        wireguard_interface=wireguard_interface,
        wireguard=wireguard,
        caddy_binary=caddy_binary,
        caddy_config=caddy_config,
        launchd_label=launchd_label,
        rendered_plist=rendered_plist,
        installed_plist=installed_plist,
        server_certificate=server_certificate,
        server_private_key=server_private_key,
        trust_topology=topology,
        services=services,
    )


def _trust_topology(services: Sequence[ServiceProbe]) -> str:
    try:
        return edge._client_trust_topology_for_paths([service.client_ca for service in services])
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc


def parse_peer(raw: str, *, server_ip: ipaddress.IPv4Address) -> ipaddress.IPv4Interface:
    if raw.count("/") != 1 or raw.rsplit("/", 1)[1] != "32":
        raise LiveCheckError("--peer must be an RFC1918 IPv4 /32")
    try:
        peer = ipaddress.ip_interface(raw)
    except ValueError as exc:
        raise LiveCheckError("--peer must be an RFC1918 IPv4 /32, for example 10.99.0.241/32") from exc
    if not isinstance(peer, ipaddress.IPv4Interface) or peer.network.prefixlen != 32:
        raise LiveCheckError("--peer must be an RFC1918 IPv4 /32")
    if not any(peer.ip in network for network in edge.RFC1918_NETWORKS):
        raise LiveCheckError("--peer must be an RFC1918 IPv4 /32")
    if peer.ip == server_ip:
        raise LiveCheckError("--peer must not be the Air server WireGuard /32")
    return peer


def _validate_server_certificate(config: LiveManifest, *, now: float | None = None) -> None:
    try:
        decoded = edge._decode_certificate(config.server_certificate)
        edge._validate_server_ip_san(config.server_certificate, config.wireguard.ip)
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc
    not_before = decoded.get("notBefore")
    not_after = decoded.get("notAfter")
    if not isinstance(not_before, str) or not isinstance(not_after, str):
        raise LiveCheckError("server certificate has no parseable validity window")
    try:
        activation = ssl.cert_time_to_seconds(not_before)
        expiry = ssl.cert_time_to_seconds(not_after)
    except ValueError as exc:
        raise LiveCheckError("server certificate has an invalid validity window") from exc
    current_time = time.time() if now is None else now
    if activation > current_time:
        raise LiveCheckError("server certificate is not yet valid")
    if expiry <= current_time:
        raise LiveCheckError("server certificate has expired")


def _launchd_pid(config: LiveManifest, runner: CommandRunner) -> int:
    service = f"gui/{os.getuid()}/{config.launchd_label}"
    result = runner([str(LAUNCHCTL_COMMAND), "print", service], 10.0)
    if result.returncode != 0 or re.search(r"^\s*state = running\s*$", result.stdout, re.MULTILINE) is None:
        raise LiveCheckError(f"Caddy LaunchAgent is not running: {service}")
    match = re.search(r"^\s*pid = ([1-9][0-9]*)\s*$", result.stdout, re.MULTILINE)
    if match is None:
        raise LiveCheckError("Caddy LaunchAgent did not report a live process ID")
    expected_lines = {
        f"path = {config.installed_plist}",
        f"program = {config.caddy_binary}",
        f"working directory = {config.caddy_config.parent}",
    }
    actual_lines = {line.strip() for line in result.stdout.splitlines()}
    if not expected_lines <= actual_lines:
        raise LiveCheckError("active Caddy LaunchAgent paths differ from the rendered contract")
    arguments = re.search(
        r"^\s*arguments = \{\s*$\n(?P<body>.*?)^\s*\}\s*$",
        result.stdout,
        re.MULTILINE | re.DOTALL,
    )
    if arguments is None:
        raise LiveCheckError("active Caddy LaunchAgent did not report its arguments")
    actual_arguments = [line.strip() for line in arguments.group("body").splitlines() if line.strip()]
    expected_arguments = [
        str(config.caddy_binary),
        "run",
        "--config",
        str(config.caddy_config),
        "--adapter",
        "caddyfile",
    ]
    if actual_arguments != expected_arguments:
        raise LiveCheckError("active Caddy LaunchAgent arguments differ from the rendered contract")
    return int(match.group(1))


def _find_executable(candidates: Sequence[Path], *, description: str) -> Path:
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise LiveCheckError(f"cannot inspect {description}: no trusted executable is available")


def _validate_process_generation(config: LiveManifest, pid: int, runner: CommandRunner) -> None:
    ps = _find_executable(PS_COMMANDS, description="Caddy process generation")
    result = runner([str(ps), "-p", str(pid), "-o", "lstart=", "-o", "command="], 10.0)
    if result.returncode != 0 or not result.stdout.strip():
        raise LiveCheckError("cannot inspect the active Caddy process generation")
    output = result.stdout.strip()
    if len(output) < 25:
        raise LiveCheckError("active Caddy process reported an invalid start time")
    try:
        started_at = time.mktime(time.strptime(output[:24], "%a %b %d %H:%M:%S %Y"))
    except ValueError as exc:
        raise LiveCheckError("active Caddy process reported an invalid start time") from exc
    expected_command = " ".join(
        (
            str(config.caddy_binary),
            "run",
            "--config",
            str(config.caddy_config),
            "--adapter",
            "caddyfile",
        )
    )
    if output[24:].strip() != expected_command:
        raise LiveCheckError("active Caddy process command differs from the rendered contract")
    if started_at + 1.0 < config.caddy_config.stat().st_mtime:
        raise LiveCheckError("active Caddy process predates the rendered config; restart it before testing")


def _validate_exact_caddyfile(config: LiveManifest) -> None:
    services = [
        edge.EdgeService(
            name=service.registry_name,
            role=service.role,
            listen_port=service.listen_port,
            upstream_port=service.upstream_port,
            client_ca=service.client_ca,
            static_root=service.static_root,
        )
        for service in config.services
    ]
    expected = edge.generate_caddyfile(
        config.wireguard.ip,
        services,
        config.server_certificate,
        config.server_private_key,
        config.path.parent / "logs",
    )
    try:
        actual = config.caddy_config.read_text()
    except UnicodeDecodeError as exc:
        raise LiveCheckError("rendered Caddy config is not UTF-8 text") from exc
    if actual != expected:
        raise LiveCheckError("rendered Caddy config differs from the exact reviewed policy")


def _parse_lsof_listeners(output: str, *, protocol: str) -> set[tuple[str, int]]:
    suffix = r"\s+\(LISTEN\)\s*$" if protocol == "TCP" else r"(?:\s|$)"
    pattern = re.compile(rf"\b{protocol}\s+(\S+):([0-9]+){suffix}")
    return {(match.group(1), int(match.group(2))) for line in output.splitlines() if (match := pattern.search(line))}


def _validate_caddy_listeners(config: LiveManifest, pid: int, runner: CommandRunner) -> None:
    lsof = _find_executable(LSOF_COMMANDS, description="Caddy listeners")
    wireguard_expected = {(str(config.wireguard.ip), urllib.parse.urlsplit(service.url).port) for service in config.services}
    if any(port is None for _, port in wireguard_expected):
        raise LiveCheckError("manifest contains a service URL without a port")
    for protocol, selector in (("TCP", "-iTCP"), ("UDP", "-iUDP")):
        command = [str(lsof), "-nP", "-a", "-p", str(pid), selector]
        if protocol == "TCP":
            command.append("-sTCP:LISTEN")
        result = runner(command, 10.0)
        if result.returncode != 0:
            raise LiveCheckError(f"cannot inspect Caddy {protocol} listeners")
        expected = set(wireguard_expected)
        if protocol == "TCP" and any(service.role == "webterm" for service in config.services):
            expected.add(("127.0.0.1", 7680))
        actual = _parse_lsof_listeners(result.stdout, protocol=protocol)
        if actual != expected:
            raise LiveCheckError(f"Caddy {protocol} listeners differ from the exact WireGuard endpoints")


def _probe_backend(service: ServiceProbe) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", service.upstream_port, timeout=3.0)
    try:
        connection.request("GET", service.health_path, headers={"Host": "127.0.0.1"})
        response = connection.getresponse()
        response.read(4096)
        return response.status
    except (OSError, http.client.HTTPException) as exc:
        raise LiveCheckError(f"{service.role} loopback backend probe failed") from exc
    finally:
        connection.close()


def check_readiness(
    config: LiveManifest,
    *,
    runner: CommandRunner = _run_command,
    backend_probe: BackendProbe = _probe_backend,
) -> dict[str, object]:
    try:
        edge._verify_wireguard_assignment(config.wireguard_interface, config.wireguard.ip)
    except edge.EdgeConfigError as exc:
        raise LiveCheckError(str(exc)) from exc
    if config.rendered_plist.read_bytes() != config.installed_plist.read_bytes():
        raise LiveCheckError("installed Caddy LaunchAgent differs from the rendered owner-only artifact")
    _validate_server_certificate(config)
    _validate_exact_caddyfile(config)

    validation = runner(
        [str(config.caddy_binary), "validate", "--config", str(config.caddy_config), "--adapter", "caddyfile"],
        30.0,
    )
    if validation.returncode != 0:
        raise LiveCheckError("caddy validate rejected the rendered Air config")
    pid = _launchd_pid(config, runner)
    _validate_process_generation(config, pid, runner)
    _validate_caddy_listeners(config, pid, runner)

    backend_status: dict[str, int] = {}
    for service in config.services:
        status_code = backend_probe(service)
        if not 200 <= status_code < 400:
            raise LiveCheckError(f"{service.role} loopback backend returned HTTP {status_code}")
        backend_status[service.role] = status_code
    return {
        "wireguard": f"{config.wireguard.ip}/32 on {config.wireguard_interface}",
        "caddy_pid": pid,
        "client_trust_topology": config.trust_topology,
        "backend_status": backend_status,
    }


def _validate_peer_route(config: LiveManifest, peer: ipaddress.IPv4Interface, runner: CommandRunner) -> None:
    route = _find_executable(PEER_ROUTE_COMMANDS, description="WireGuard peer route")
    result = runner([str(route), "-n", "get", str(peer.ip)], 10.0)
    if result.returncode != 0:
        raise LiveCheckError(f"no route to peer {peer}")
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    if match is None or match.group(1) != config.wireguard_interface:
        raise LiveCheckError(f"peer {peer} is not routed through {config.wireguard_interface}")


def _new_cursor(path: Path) -> LogCursor:
    _owner_only_file(path, description="live-smoke access log")
    info = path.stat()
    return LogCursor(path=path, device=info.st_dev, inode=info.st_ino, offset=info.st_size)


def _read_new_entries(cursor: LogCursor) -> list[dict]:
    _owner_only_file(cursor.path, description="live-smoke access log")
    info = cursor.path.stat()
    if (info.st_dev, info.st_ino) != (cursor.device, cursor.inode) or info.st_size < cursor.offset:
        cursor.device, cursor.inode, cursor.offset, cursor.partial = info.st_dev, info.st_ino, 0, b""
    with cursor.path.open("rb") as handle:
        handle.seek(cursor.offset)
        chunk = handle.read()
        cursor.offset = handle.tell()
    complete = cursor.partial + chunk
    lines = complete.split(b"\n")
    cursor.partial = lines.pop()
    entries: list[dict] = []
    for line in lines:
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LiveCheckError(f"{cursor.path.name} contains a malformed new JSON access record") from exc
        if not isinstance(decoded, dict):
            raise LiveCheckError(f"{cursor.path.name} contains a non-object access record")
        entries.append(decoded)
    return entries


def _matches_probe_entry(
    entry: dict,
    *,
    service: ServiceProbe,
    peer_ip: ipaddress.IPv4Address,
    nonce: str,
    started_at: float,
) -> tuple[bool, int | None]:
    request = entry.get("request")
    if not isinstance(request, dict):
        return False, None
    parsed_url = urllib.parse.urlsplit(service.url)
    expected_host = parsed_url.netloc
    if (
        request.get("remote_ip") != str(peer_ip)
        or request.get("method") != "GET"
        or request.get("host") != expected_host
    ):
        return False, None
    if entry.get(service.probe_token_field) != nonce or entry.get(service.probe_path_field) != service.health_path:
        return False, None
    timestamp = entry.get("ts")
    if not isinstance(timestamp, int | float) or timestamp < started_at - 1.0:
        return False, None
    status_code = entry.get("status")
    if not isinstance(status_code, int):
        return True, None
    return True, status_code


def peer_smoke(
    config: LiveManifest,
    *,
    peer: ipaddress.IPv4Interface,
    timeout: float,
    runner: CommandRunner = _run_command,
    nonce: str | None = None,
) -> dict[str, int]:
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise LiveCheckError(f"--timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    _validate_peer_route(config, peer, runner)
    cursors = {service.role: _new_cursor(service.access_log) for service in config.services}
    nonce = secrets.token_urlsafe(18) if nonce is None else nonce
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise LiveCheckError("generated live-smoke correlation value is malformed")
    started_at = time.time()

    print(f"Open each URL on the peer at {peer} while its WireGuard tunnel is active:")
    for service in config.services:
        query = urllib.parse.urlencode({service.query_parameter: nonce})
        parsed = urllib.parse.urlsplit(service.url)
        target = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, service.health_path, query, ""))
        print(f"  {service.role}: {target}")
    print("Waiting for authenticated peer requests; Air will not connect to its own WireGuard /32.")
    sys.stdout.flush()

    passed: dict[str, int] = {}
    failed_status: dict[str, int | None] = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(passed) < len(config.services):
        for service in config.services:
            if service.role in passed:
                continue
            for entry in _read_new_entries(cursors[service.role]):
                matched, status_code = _matches_probe_entry(
                    entry,
                    service=service,
                    peer_ip=peer.ip,
                    nonce=nonce,
                    started_at=started_at,
                )
                if not matched:
                    continue
                if status_code is not None and 200 <= status_code < 400:
                    passed[service.role] = status_code
                    print(f"ok: {service.role} peer smoke returned HTTP {status_code}")
                    break
                failed_status[service.role] = status_code
        if len(passed) < len(config.services):
            time.sleep(POLL_INTERVAL_SECONDS)
    if len(passed) != len(config.services):
        missing = sorted(set(service.role for service in config.services) - set(passed))
        details = ", ".join(
            f"{role}=HTTP {failed_status[role]}" if role in failed_status else f"{role}=no matching request"
            for role in missing
        )
        raise LiveCheckError(f"peer smoke timed out ({details})")
    return passed


def _print_readiness(report: dict[str, object]) -> None:
    print("macOS Air live readiness passed")
    print(f"  WireGuard: {report['wireguard']}")
    print(f"  Caddy PID: {report['caddy_pid']}")
    print(f"  client trust topology: {report['client_trust_topology']}")
    backend_status = report["backend_status"]
    assert isinstance(backend_status, dict)
    for role, status_code in backend_status.items():
        print(f"  {role} loopback backend: HTTP {status_code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Owner-only rendered manifest path")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("readiness", help="Check live local state without contacting the WireGuard /32.")
    peer_parser = subparsers.add_parser("peer", help="Wait for live-smoke requests from one independent mesh peer.")
    peer_parser.add_argument("--peer", required=True, help="Expected RFC1918 WireGuard peer /32.")
    peer_parser.add_argument("--timeout", type=float, default=90.0, help="Wait timeout in seconds (maximum 600).")
    args = parser.parse_args(argv)

    try:
        config = load_manifest(Path(args.manifest))
        report = check_readiness(config)
        _print_readiness(report)
        if args.command == "peer":
            peer = parse_peer(args.peer, server_ip=config.wireguard.ip)
            peer_smoke(config, peer=peer, timeout=args.timeout)
            print(f"peer integration passed from {peer}")
    except (LiveCheckError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
