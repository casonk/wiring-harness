from __future__ import annotations

import importlib.util
import io
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
SPEC = importlib.util.spec_from_file_location(
    "check_macos_air_live",
    SCRIPTS_DIR / "check_macos_air_live.py",
)
assert SPEC is not None and SPEC.loader is not None
live = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = live
SPEC.loader.exec_module(live)

FAKE_CERT = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
FAKE_KEY = "-----BEGIN " + "PRIVATE KEY-----\nZmFrZQ==\n-----END " + "PRIVATE KEY-----\n"


class MacOSAirLiveCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.edge_dir = self.root / "edge.local"
        self.logs = self.edge_dir / "logs"
        self.certs = self.root / "certs"
        self.bin_dir = self.root / "bin"
        for directory in (self.edge_dir, self.logs, self.certs, self.bin_dir):
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        self.caddy = self.bin_dir / "caddy"
        self.caddy.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(self.caddy, 0o700)
        self.lsof = self.bin_dir / "lsof"
        self.route = self.bin_dir / "route"
        self.ps = self.bin_dir / "ps"
        for executable in (self.lsof, self.route, self.ps):
            executable.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(executable, 0o700)
        self.command_paths = mock.patch.multiple(
            live,
            LSOF_COMMANDS=(self.lsof,),
            PEER_ROUTE_COMMANDS=(self.route,),
            PS_COMMANDS=(self.ps,),
        )
        self.command_paths.start()
        self.addCleanup(self.command_paths.stop)
        self.trust_authorities = mock.patch.object(
            live.edge,
            "_certificate_trust_authority",
            side_effect=lambda block, path: block.encode(),
        )
        self.trust_authorities.start()
        self.addCleanup(self.trust_authorities.stop)
        self.caddyfile = self._write_private(self.edge_dir / "Caddyfile", "")
        self.rendered_plist = self._write_private(self.edge_dir / f"{live.edge.LAUNCHD_LABEL}.plist", "plist\n")
        self.installed_plist = self._write_private(self.root / "installed.plist", "plist\n")
        self.server_cert = self._write_private(self.certs / "server.crt", FAKE_CERT)
        self.server_key = self._write_private(self.certs / "server.key", FAKE_KEY)
        self.shared_ca = self._write_private(self.certs / "ca.crt", FAKE_CERT)
        self.manifest_path = self.edge_dir / "manifest.json"
        self._write_manifest()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _private(path: Path) -> Path:
        os.chmod(path, 0o600)
        return path

    def _write_private(self, path: Path, content: str) -> Path:
        path.write_text(content)
        return self._private(path)

    def _service(self, role: str, *, client_ca: Path | None = None) -> dict:
        listen_port = live.edge.REVIEWED_ROLES[role].default_listen_port
        upstream_port = live.edge.REVIEWED_ROLES[role].upstream_port
        access_log = self._write_private(self.logs / f"{role}.access.json", "")
        return {
            "registry_name": f"{role}-service",
            "role": role,
            "url": f"https://10.99.0.254:{listen_port}/",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "client_ca": str(client_ca or self.shared_ca),
            "access_log": {
                "path": str(access_log),
                "scope": "live-smoke-query-only",
                "format": "json",
                "query_parameter": live.edge.LIVE_SMOKE_QUERY_PARAMETER,
                "query_value_filter": "opaque-non-secret",
                "request_uri": "deleted",
                "probe_token_field": live.edge.LIVE_SMOKE_LOG_TOKEN_FIELD,
                "probe_path_field": live.edge.LIVE_SMOKE_LOG_PATH_FIELD,
                "mode": "0600",
                "roll_size_mib": 1,
                "roll_keep": 2,
            },
            "proxy_auth_header_override": None,
        }

    def _write_manifest(self, *, services: list[dict] | None = None, topology: str = "shared") -> None:
        if services is None:
            services = [self._service("clockwork"), self._service("snowbridge")]
        edge_services = [
            live.edge.EdgeService(
                name=service["registry_name"],
                role=service["role"],
                listen_port=live.edge.REVIEWED_ROLES[service["role"]].default_listen_port,
                upstream_port=live.edge.REVIEWED_ROLES[service["role"]].upstream_port,
                client_ca=Path(service["client_ca"]),
            )
            for service in services
        ]
        self.caddyfile.write_text(
            live.edge.generate_caddyfile(
                ipaddress.ip_address("10.99.0.254"),
                edge_services,
                self.server_cert,
                self.server_key,
                self.logs,
            )
        )
        self._private(self.caddyfile)
        manifest = {
            "schema_version": live.edge.MANIFEST_SCHEMA_VERSION,
            "activation": "render-only",
            "wireguard_interface": "utun7",
            "wireguard_bind": "10.99.0.254/32",
            "uses_private_dns": False,
            "server_certificate_required_ip_san": "10.99.0.254",
            "client_auth": "require_and_verify",
            "default_sni": "10.99.0.254",
            "strict_sni_host": "insecure_off-after-default-sni",
            "client_trust_topology": topology,
            "tls": {
                "server_certificate": str(self.server_cert),
                "server_private_key": str(self.server_key),
            },
            "launchd": {
                "scope": "user",
                "label": live.edge.LAUNCHD_LABEL,
                "rendered_plist": str(self.rendered_plist),
                "install_target": str(self.installed_plist),
                "privileged_ports_allowed": False,
            },
            "caddy": {
                "binary": str(self.caddy),
                "installed": True,
                "validated": True,
                "config": str(self.caddyfile),
                "admin_api": "off",
                "automatic_http_redirects": "off",
            },
            "services": services,
        }
        self.manifest_path.write_text(json.dumps(manifest))
        self._private(self.manifest_path)

    @staticmethod
    def _decoded_cert(*, expired: bool = False) -> dict:
        return {
            "subjectAltName": (("IP Address", "10.99.0.254"),),
            "notBefore": "Aug 11 07:49:10 2020 GMT",
            "notAfter": "Aug 11 07:49:10 2020 GMT" if expired else "Sep 12 07:49:10 2037 GMT",
        }

    def _runner(
        self,
        commands: list[list[str]] | None = None,
        *,
        wrong_listener: bool = False,
        stale_process: bool = False,
    ):
        def run(command, _timeout):
            command = list(command)
            if commands is not None:
                commands.append(command)
            executable = Path(command[0]).name
            if executable == "caddy":
                return subprocess.CompletedProcess(command, 0, "Valid configuration\n", "")
            if executable == "launchctl":
                output = f"""path = {self.installed_plist}
state = running
program = {self.caddy}
arguments = {{
    {self.caddy}
    run
    --config
    {self.caddyfile}
    --adapter
    caddyfile
}}
working directory = {self.edge_dir}
pid = 1234
"""
                return subprocess.CompletedProcess(command, 0, output, "")
            if executable == "ps":
                started = (
                    "Tue Aug 11 18:05:05 2020"
                    if stale_process
                    else time.strftime(
                        "%a %b %d %H:%M:%S %Y",
                        time.localtime(),
                    )
                )
                process = f"{self.caddy} run --config {self.caddyfile} --adapter caddyfile"
                return subprocess.CompletedProcess(command, 0, f"{started}     {process}\n", "")
            if executable == "lsof":
                address = "0.0.0.0" if wrong_listener else "10.99.0.254"
                protocol = "TCP" if "-iTCP" in command else "UDP"
                suffix = " (LISTEN)" if protocol == "TCP" else ""
                output = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                output += f"caddy 1234 user 6u IPv4 0 0t0 {protocol} {address}:8443{suffix}\n"
                output += f"caddy 1234 user 7u IPv4 0 0t0 {protocol} {address}:8444{suffix}\n"
                return subprocess.CompletedProcess(command, 0, output, "")
            if executable == "route":
                return subprocess.CompletedProcess(command, 0, "interface: utun7\n", "")
            raise AssertionError(f"unexpected command: {command}")

        return run

    def _load(self):
        return live.load_manifest(self.manifest_path)

    def test_loads_shared_trust_topology_and_strict_probe_logs(self) -> None:
        config = self._load()

        self.assertEqual(config.trust_topology, "shared")
        self.assertEqual([service.role for service in config.services], ["clockwork", "snowbridge"])
        self.assertTrue(all(service.query_parameter == "wiring_harness_smoke" for service in config.services))

    def test_reports_distinct_trust_topology_by_file_content(self) -> None:
        snow_ca = self._write_private(self.certs / "snow-ca.crt", FAKE_CERT.replace("ZmFrZQ==", "c25vdw=="))
        services = [self._service("clockwork"), self._service("snowbridge", client_ca=snow_ca)]
        self._write_manifest(services=services, topology="distinct")

        self.assertEqual(self._load().trust_topology, "distinct")

    def test_reports_overlapping_trust_bundles_without_claiming_isolation(self) -> None:
        second_cert = FAKE_CERT.replace("ZmFrZQ==", "c2Vjb25k")
        third_cert = FAKE_CERT.replace("ZmFrZQ==", "dGhpcmQ=")
        clockwork_ca = self._write_private(self.certs / "clockwork-bundle.crt", FAKE_CERT + second_cert)
        snow_ca = self._write_private(self.certs / "snow-bundle.crt", FAKE_CERT + third_cert)
        services = [
            self._service("clockwork", client_ca=clockwork_ca),
            self._service("snowbridge", client_ca=snow_ca),
        ]
        self._write_manifest(services=services, topology="overlapping")

        self.assertEqual(self._load().trust_topology, "overlapping")

    def test_rejects_manifest_topology_drift(self) -> None:
        self._write_manifest(topology="distinct")

        with self.assertRaisesRegex(live.LiveCheckError, "topology has drifted"):
            self._load()

    def test_rejects_access_log_outside_rendered_log_directory(self) -> None:
        service = self._service("clockwork")
        outside = self._write_private(self.root / "outside.json", "")
        service["access_log"]["path"] = str(outside)
        self._write_manifest(services=[service], topology="single")

        with self.assertRaisesRegex(live.LiveCheckError, "inside the rendered"):
            self._load()

    def test_rejects_unsafe_access_log_directory_or_roll(self) -> None:
        os.chmod(self.logs, 0o755)
        with self.assertRaisesRegex(live.LiveCheckError, "owner-only|mode 0700"):
            self._load()

        os.chmod(self.logs, 0o700)
        rolled = self.logs / "clockwork.access-2026-08-16T12-00-00.000-size.json"
        rolled.write_text("{}\n")
        os.chmod(rolled, 0o644)
        with self.assertRaisesRegex(live.LiveCheckError, "owner-only|mode 0600"):
            self._load()

    def test_peer_requires_distinct_rfc1918_ipv4_32(self) -> None:
        server = ipaddress.ip_address("10.99.0.254")
        self.assertEqual(str(live.parse_peer("10.99.0.241/32", server_ip=server)), "10.99.0.241/32")
        for value in (
            "10.99.0.241",
            "10.99.0.241/255.255.255.255",
            "10.99.0.241/24",
            "203.0.113.7/32",
            "10.99.0.254/32",
            "fd00::1/128",
        ):
            with self.subTest(value=value), self.assertRaises(live.LiveCheckError):
                live.parse_peer(value, server_ip=server)

    def test_readiness_checks_exact_live_boundaries_and_loopback_backends(self) -> None:
        config = self._load()
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(
                live.edge,
                "_interface_ipv4_addresses",
                return_value={ipaddress.ip_address("10.99.0.254")},
            ),
        ):
            report = live.check_readiness(config, runner=self._runner(), backend_probe=lambda _service: 200)

        self.assertEqual(report["caddy_pid"], 1234)
        self.assertEqual(report["client_trust_topology"], "shared")
        self.assertEqual(report["backend_status"], {"clockwork": 200, "snowbridge": 200})

    def test_readiness_rejects_listener_or_installed_plist_drift(self) -> None:
        config = self._load()
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(
                live.edge,
                "_interface_ipv4_addresses",
                return_value={ipaddress.ip_address("10.99.0.254")},
            ),
            self.assertRaisesRegex(live.LiveCheckError, "listeners differ"),
        ):
            live.check_readiness(config, runner=self._runner(wrong_listener=True), backend_probe=lambda _service: 200)

        self.installed_plist.write_text("drifted\n")
        with (
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
            self.assertRaisesRegex(live.LiveCheckError, "differs from the rendered"),
        ):
            live.check_readiness(config, runner=self._runner(), backend_probe=lambda _service: 200)

    def test_readiness_rejects_expired_certificate_or_unhealthy_backend(self) -> None:
        config = self._load()
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert(expired=True)),
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
            self.assertRaisesRegex(live.LiveCheckError, "expired"),
        ):
            live.check_readiness(config, runner=self._runner(), backend_probe=lambda _service: 200)

        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
            self.assertRaisesRegex(live.LiveCheckError, "HTTP 503"),
        ):
            live.check_readiness(config, runner=self._runner(), backend_probe=lambda _service: 503)

    def test_readiness_rejects_caddy_policy_drift_or_stale_process(self) -> None:
        config = self._load()
        self.caddyfile.write_text(self.caddyfile.read_text() + "# drift\n")
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
            self.assertRaisesRegex(live.LiveCheckError, "exact reviewed policy"),
        ):
            live.check_readiness(config, runner=self._runner(), backend_probe=lambda _service: 200)

        self._write_manifest()
        config = self._load()
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
            self.assertRaisesRegex(live.LiveCheckError, "predates the rendered config"),
        ):
            live.check_readiness(
                config,
                runner=self._runner(stale_process=True),
                backend_probe=lambda _service: 200,
            )

    def test_peer_smoke_matches_only_fresh_peer_records(self) -> None:
        config = self._load()
        peer = live.parse_peer("10.99.0.241/32", server_ip=config.wireguard.ip)
        nonce = "A" * 24

        def entries(cursor):
            role = cursor.path.name.split(".", 1)[0]
            service = next(item for item in config.services if item.role == role)
            return [
                {
                    "ts": time.time(),
                    "request": {
                        "remote_ip": str(peer.ip),
                        "method": "GET",
                        "host": urllib.parse.urlsplit(service.url).netloc,
                    },
                    service.probe_token_field: nonce,
                    service.probe_path_field: service.health_path,
                    "status": 200,
                }
            ]

        with mock.patch.object(live, "_read_new_entries", side_effect=entries), redirect_stdout(io.StringIO()):
            passed = live.peer_smoke(config, peer=peer, timeout=1, runner=self._runner(), nonce=nonce)

        self.assertEqual(passed, {"clockwork": 200, "snowbridge": 200})

    def test_probe_record_requires_fresh_exact_correlation_and_preserves_failure_status(self) -> None:
        config = self._load()
        service = config.services[0]
        peer_ip = ipaddress.ip_address("10.99.0.241")
        nonce = "D" * 24
        started_at = time.time()
        entry = {
            "ts": started_at,
            "request": {
                "remote_ip": str(peer_ip),
                "method": "GET",
                "host": urllib.parse.urlsplit(service.url).netloc,
            },
            service.probe_token_field: nonce,
            service.probe_path_field: service.health_path,
            "status": 503,
        }

        self.assertEqual(
            live._matches_probe_entry(
                entry,
                service=service,
                peer_ip=peer_ip,
                nonce=nonce,
                started_at=started_at,
            ),
            (True, 503),
        )
        for field, value in (
            ("ts", started_at - 2),
            (service.probe_token_field, "E" * 24),
            (service.probe_path_field, "/wrong"),
        ):
            with self.subTest(field=field):
                drifted = dict(entry)
                drifted[field] = value
                self.assertEqual(
                    live._matches_probe_entry(
                        drifted,
                        service=service,
                        peer_ip=peer_ip,
                        nonce=nonce,
                        started_at=started_at,
                    ),
                    (False, None),
                )

    def test_peer_smoke_rejects_wrong_peer_and_times_out(self) -> None:
        config = self._load()
        peer = live.parse_peer("10.99.0.241/32", server_ip=config.wireguard.ip)
        nonce = "B" * 24

        def entries(cursor):
            role = cursor.path.name.split(".", 1)[0]
            service = next(item for item in config.services if item.role == role)
            return [
                {
                    "ts": time.time(),
                    "request": {
                        "remote_ip": "10.99.0.242",
                        "method": "GET",
                        "host": urllib.parse.urlsplit(service.url).netloc,
                    },
                    service.probe_token_field: nonce,
                    service.probe_path_field: service.health_path,
                    "status": 200,
                }
            ]

        with (
            mock.patch.object(live, "_read_new_entries", side_effect=entries),
            mock.patch.object(live, "POLL_INTERVAL_SECONDS", 0),
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(live.LiveCheckError, "no matching request"),
        ):
            live.peer_smoke(config, peer=peer, timeout=0.001, runner=self._runner(), nonce=nonce)

    def test_commands_never_target_the_air_wireguard_address(self) -> None:
        config = self._load()
        commands: list[list[str]] = []
        with (
            mock.patch.object(live.edge, "_decode_certificate", return_value=self._decoded_cert()),
            mock.patch.object(live.edge, "_interface_ipv4_addresses", return_value={config.wireguard.ip}),
        ):
            live.check_readiness(
                config,
                runner=self._runner(commands),
                backend_probe=lambda service: 200 if service.upstream_port in {5001, 8080} else 500,
            )
        peer = live.parse_peer("10.99.0.241/32", server_ip=config.wireguard.ip)
        with (
            mock.patch.object(live, "_read_new_entries", return_value=[]),
            mock.patch.object(live, "POLL_INTERVAL_SECONDS", 0),
            redirect_stdout(io.StringIO()),
            self.assertRaises(live.LiveCheckError),
        ):
            live.peer_smoke(config, peer=peer, timeout=0.001, runner=self._runner(commands), nonce="C" * 24)

        flattened = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn("https://10.99.0.254", flattened)
        self.assertNotRegex(flattened, r"(?:curl|wget).*10\.99\.0\.254")


if __name__ == "__main__":
    unittest.main()
