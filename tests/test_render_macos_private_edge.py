from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
SPEC = importlib.util.spec_from_file_location(
    "render_macos_private_edge",
    SCRIPTS_DIR / "render_macos_private_edge.py",
)
assert SPEC is not None and SPEC.loader is not None
edge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = edge
SPEC.loader.exec_module(edge)


FAKE_CERT = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
FAKE_KEY = "-----BEGIN " + "PRIVATE KEY-----\nZmFrZQ==\n-----END " + "PRIVATE KEY-----\n"


class MacOSPrivateEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.services = self.root / "services.toml"
        self.services.write_text("# public base registry\n")
        self.local_services = self.root / "services.local.toml"
        self.certs = self.root / "certs"
        self.certs.mkdir(mode=0o700)
        os.chmod(self.certs, 0o700)
        for name, content in (
            ("server.crt", FAKE_CERT),
            ("server.key", FAKE_KEY),
            ("ca.crt", FAKE_CERT),
        ):
            path = self.certs / name
            path.write_text(content)
            os.chmod(path, 0o600)
        self.output = self.root / "edge.local"
        self.caddy = self.root / "bin" / "caddy"
        self._write_registry()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_registry(
        self,
        *,
        wireguard_interface: str = "utun7",
        wireguard_address: str = "10.99.0.254/32",
        clockwork_port: int = 5001,
        listen_port: int = 8443,
        include_snowbridge: bool = False,
        include_webterm: bool = False,
        snowbridge_client_ca: Path | None = None,
        extra_clockwork: str = "",
    ) -> None:
        snowbridge = ""
        if include_snowbridge:
            client_ca = f'client_ca_path         = "{snowbridge_client_ca}"\n' if snowbridge_client_ca else ""
            snowbridge = f"""

[[services]]
name                   = "snowbridge-filebrowser"
description            = "Files"
owner_repo             = "./util-repos/snowbridge"
hostname               = "files.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 8080
{client_ca}macos_edge_role        = "snowbridge"
macos_edge_listen_port = 8444
"""
        webterm = ""
        if include_webterm:
            webterm = """

[[services]]
name                   = "pit-box-webterm"
description            = "Web terminal"
owner_repo             = "./util-repos/pit-box"
hostname               = "webterm.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 7681
macos_edge_role        = "webterm"
macos_edge_listen_port = 8445
"""
        self.local_services.write_text(f"""[macos_private_edge]
wireguard_interface = "{wireguard_interface}"
wireguard_address = "{wireguard_address}"

[[services]]
name                   = "clockwork-web"
description            = "Scheduler"
owner_repo             = "./util-repos/clockwork"
hostname               = "clockwork.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = {clockwork_port}
macos_edge_role        = "clockwork"
macos_edge_listen_port = {listen_port}
{extra_clockwork}{snowbridge}{webterm}
""")
        os.chmod(self.local_services, 0o600)

    def _render(self, **kwargs) -> dict:
        decoded = {"subjectAltName": (("IP Address", "10.99.0.254"),)}
        with (
            mock.patch.object(edge, "_decode_certificate", return_value=decoded),
            mock.patch.object(
                edge,
                "_interface_ipv4_addresses",
                return_value={ipaddress.ip_address("10.99.0.254")},
            ),
            mock.patch.object(
                edge,
                "_certificate_trust_authority",
                side_effect=lambda block, path: block.encode(),
            ),
        ):
            return edge.render_bundle(
                services_path=self.services,
                certs_dir=self.certs,
                output_dir=self.output,
                caddy_binary=self.caddy,
                **kwargs,
            )

    def test_renders_ip_literal_mtls_edge_and_inert_user_launch_agent(self) -> None:
        manifest = self._render()
        caddyfile = (self.output / "Caddyfile").read_text()
        plist_path = self.output / f"{edge.LAUNCHD_LABEL}.plist"
        plist = plistlib.loads(plist_path.read_bytes())

        self.assertIn("https://10.99.0.254:8443", caddyfile)
        self.assertIn("bind 10.99.0.254", caddyfile)
        self.assertIn("mode require_and_verify", caddyfile)
        self.assertIn("default_sni 10.99.0.254", caddyfile)
        self.assertIn("strict_sni_host insecure_off", caddyfile)
        self.assertIn("reverse_proxy 127.0.0.1:5001", caddyfile)
        self.assertNotIn("clockwork.air.internal", caddyfile)
        self.assertNotIn("0.0.0.0", caddyfile)
        self.assertNotIn("import ", caddyfile)
        self.assertEqual(manifest["server_certificate_required_ip_san"], "10.99.0.254")
        self.assertEqual(manifest["wireguard_interface"], "utun7")
        self.assertFalse(manifest["uses_private_dns"])
        self.assertEqual(manifest["activation"], "render-only")
        self.assertEqual(manifest["default_sni"], "10.99.0.254")
        self.assertEqual(manifest["strict_sni_host"], "insecure_off-after-default-sni")
        self.assertEqual(plist["ProgramArguments"][0], str(self.caddy))
        self.assertEqual(plist["ProgramArguments"][1], "run")
        self.assertEqual(plist["Umask"], 0o077)
        self.assertEqual(oct(self.output.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((self.output / "Caddyfile").stat().st_mode & 0o777), "0o600")
        access_log = self.output / "logs" / "clockwork.access.json"
        self.assertEqual(oct(access_log.stat().st_mode & 0o777), "0o600")
        self.assertIn("@wiringHarnessSmoke `method('GET') && path('/')", caddyfile)
        self.assertIn("@notWiringHarnessSmoke `!(method('GET') && path('/')", caddyfile)
        self.assertIn("matches('^[A-Za-z0-9_-]{16,128}$')", caddyfile)
        self.assertIn(
            "log_append @wiringHarnessSmoke wiring_harness_smoke {query.wiring_harness_smoke}",
            caddyfile,
        )
        self.assertIn("log_append @wiringHarnessSmoke wiring_harness_path {path}", caddyfile)
        self.assertIn("log_skip @notWiringHarnessSmoke", caddyfile)
        self.assertIn(f"output file {access_log}", caddyfile)
        self.assertIn("mode 0600", caddyfile)
        self.assertIn("roll_size 1MiB", caddyfile)
        self.assertIn("roll_keep 2", caddyfile)
        self.assertIn("request>headers delete", caddyfile)
        self.assertIn("request>tls delete", caddyfile)
        self.assertIn("request>uri delete", caddyfile)
        self.assertIn("resp_headers delete", caddyfile)
        self.assertNotIn("query_value_filter sha256", caddyfile)
        self.assertEqual(manifest["schema_version"], edge.MANIFEST_SCHEMA_VERSION)
        self.assertEqual(manifest["client_trust_topology"], "single")
        self.assertEqual(manifest["tls"]["server_private_key"], str(self.certs / "server.key"))
        self.assertEqual(manifest["services"][0]["access_log"]["scope"], "live-smoke-query-only")
        self.assertEqual(manifest["services"][0]["access_log"]["request_uri"], "deleted")
        self.assertEqual(
            manifest["services"][0]["access_log"]["probe_token_field"],
            "wiring_harness_smoke",
        )
        self.assertEqual(
            manifest["services"][0]["access_log"]["probe_path_field"],
            "wiring_harness_path",
        )
        self.assertEqual(manifest["services"][0]["access_log"]["mode"], "0600")
        self.assertFalse(manifest["launchd"]["privileged_ports_allowed"])

    def test_optional_snowbridge_uses_separate_ip_literal_port(self) -> None:
        self._write_registry(include_snowbridge=True)
        manifest = self._render()
        caddyfile = (self.output / "Caddyfile").read_text()

        self.assertIn("https://10.99.0.254:8444", caddyfile)
        self.assertIn("reverse_proxy 127.0.0.1:8080", caddyfile)
        self.assertIn('header_up X-Snowbridge-Auth-User "snowbridge"', caddyfile)
        self.assertEqual(caddyfile.count("X-Snowbridge-Auth-User"), 1)
        self.assertEqual([item["role"] for item in manifest["services"]], ["clockwork", "snowbridge"])
        self.assertEqual(manifest["client_trust_topology"], "shared")
        for service in manifest["services"]:
            access_log = Path(service["access_log"]["path"])
            self.assertTrue(access_log.is_file())
            self.assertEqual(oct(access_log.stat().st_mode & 0o777), "0o600")
        self.assertIsNone(manifest["services"][0]["proxy_auth_header_override"])
        self.assertEqual(
            manifest["services"][1]["proxy_auth_header_override"],
            {"header": "X-Snowbridge-Auth-User", "value": "snowbridge"},
        )

    def test_optional_webterm_uses_its_reviewed_loopback_port(self) -> None:
        self._write_registry(include_webterm=True)
        manifest = self._render()
        caddyfile = (self.output / "Caddyfile").read_text()

        self.assertIn("https://10.99.0.254:8445", caddyfile)
        self.assertIn("reverse_proxy 127.0.0.1:7681", caddyfile)
        self.assertIn("rewrite * /home.html", caddyfile)
        self.assertIn("@term_ttyd path /term/token /term/ws", caddyfile)
        self.assertEqual([item["role"] for item in manifest["services"]], ["clockwork", "webterm"])
        self.assertIsNone(manifest["services"][1]["proxy_auth_header_override"])

    def test_manifest_reports_distinct_client_trust_files_by_content(self) -> None:
        snow_ca = self.certs / "snow-ca.crt"
        snow_ca.write_text(FAKE_CERT.replace("ZmFrZQ==", "c25vdw=="))
        os.chmod(snow_ca, 0o600)
        self._write_registry(include_snowbridge=True, snowbridge_client_ca=snow_ca)

        manifest = self._render()

        self.assertEqual(manifest["client_trust_topology"], "distinct")
        self.assertEqual(manifest["services"][1]["client_ca"], str(snow_ca))

    def test_rerender_preserves_existing_access_log_content(self) -> None:
        self._render()
        access_log = self.output / "logs" / "clockwork.access.json"
        access_log.write_text('{"status":200}\n')

        self._render()

        self.assertEqual(access_log.read_text(), '{"status":200}\n')

    def test_rejects_non_owner_only_existing_access_log(self) -> None:
        self._render()
        access_log = self.output / "logs" / "clockwork.access.json"
        os.chmod(access_log, 0o640)

        with self.assertRaisesRegex(edge.EdgeConfigError, "mode 0600"):
            self._render()

    def test_rejects_unsafe_or_unbounded_access_log_roll_state(self) -> None:
        self._render()
        logs = self.output / "logs"
        rolled = logs / "clockwork.access-2026-08-16T12-00-00.000-size.json"
        rolled.write_text("{}\n")
        os.chmod(rolled, 0o644)
        with self.assertRaisesRegex(edge.EdgeConfigError, "owner-only|mode 0600"):
            self._render()

        os.chmod(rolled, 0o600)
        for index in (1, 2):
            extra = logs / f"clockwork.access-2026-08-16T12-00-0{index}.000-size.json"
            extra.write_text("{}\n")
            os.chmod(extra, 0o600)
        with self.assertRaisesRegex(edge.EdgeConfigError, "roll count"):
            self._render()

    def test_rejects_nonprivate_access_log_directory_or_oversize_current_log(self) -> None:
        self._render()
        logs = self.output / "logs"
        os.chmod(logs, 0o755)
        with self.assertRaisesRegex(edge.EdgeConfigError, "owner-only"):
            self._render()

        os.chmod(logs, 0o700)
        access_log = logs / "clockwork.access.json"
        with access_log.open("wb") as handle:
            handle.truncate(edge.ACCESS_LOG_ROLL_SIZE_MIB * 1024 * 1024 + edge.ACCESS_LOG_MAX_RECORD_BYTES + 1)
        with self.assertRaisesRegex(edge.EdgeConfigError, "size bound"):
            self._render()

    def test_rejects_non_host_or_public_wireguard_bind(self) -> None:
        for address in ("10.99.0.254/24", "0.0.0.0/32", "203.0.113.10/32"):
            with self.subTest(address=address):
                self._write_registry(wireguard_address=address)
                with self.assertRaises(edge.EdgeConfigError):
                    self._render()

    def test_rejects_non_utun_interface(self) -> None:
        self._write_registry(wireguard_interface="en0")
        with self.assertRaisesRegex(edge.EdgeConfigError, "match utun"):
            self._render()

    def test_rejects_address_not_assigned_to_declared_wireguard_interface(self) -> None:
        decoded = {"subjectAltName": (("IP Address", "10.99.0.254"),)}
        with (
            mock.patch.object(edge, "_decode_certificate", return_value=decoded),
            mock.patch.object(edge, "_interface_ipv4_addresses", return_value=set()),
            self.assertRaisesRegex(edge.EdgeConfigError, "not assigned to interface utun7"),
        ):
            edge.render_bundle(
                services_path=self.services,
                certs_dir=self.certs,
                output_dir=self.output,
                caddy_binary=self.caddy,
            )

    def test_rejects_hardlinked_existing_output(self) -> None:
        self._render()
        caddyfile = self.output / "Caddyfile"
        hardlink = self.root / "caddy-hardlink"
        os.link(caddyfile, hardlink)
        with self.assertRaisesRegex(edge.EdgeConfigError, "exactly one hard link"):
            self._render()

    def test_rejects_any_nonreviewed_edge_port(self) -> None:
        for listen_port in (443, 9443):
            with self.subTest(listen_port=listen_port):
                self._write_registry(listen_port=listen_port)
                with self.assertRaisesRegex(edge.EdgeConfigError, "reviewed port 8443"):
                    self._render()

    def test_rejects_unreviewed_clockwork_upstream(self) -> None:
        self._write_registry(clockwork_port=5000)
        with self.assertRaisesRegex(edge.EdgeConfigError, "127.0.0.1:5001"):
            self._render()

    def test_rejects_placeholder_paths(self) -> None:
        self._write_registry(extra_clockwork='client_ca_path = "/Users/<user>/ca.crt"')
        with self.assertRaisesRegex(edge.EdgeConfigError, "placeholder"):
            self._render()

    def test_rejects_group_readable_local_registry(self) -> None:
        os.chmod(self.local_services, 0o640)
        with self.assertRaisesRegex(edge.EdgeConfigError, "owner-only"):
            self._render()

    def test_rejects_group_readable_private_key(self) -> None:
        os.chmod(self.certs / "server.key", 0o640)
        with self.assertRaisesRegex(edge.EdgeConfigError, "owner-only"):
            self._render()

    def test_rejects_placeholder_private_key(self) -> None:
        (self.certs / "server.key").write_text("<replace-me-with-a-private-key>\n")
        with self.assertRaisesRegex(edge.EdgeConfigError, "PEM private key|placeholder"):
            self._render()

    def test_rejects_server_certificate_without_wireguard_ip_san(self) -> None:
        decoded = {"subjectAltName": (("DNS", "clockwork.air.internal"),)}
        with (
            mock.patch.object(edge, "_decode_certificate", return_value=decoded),
            # Without this the interface probe reaches the real host, so the render
            # fails on a missing utun7 wherever the tunnel is down -- including CI --
            # long before it can reject the certificate this test is about.
            mock.patch.object(
                edge,
                "_interface_ipv4_addresses",
                return_value={ipaddress.ip_address("10.99.0.254")},
            ),
            self.assertRaisesRegex(edge.EdgeConfigError, "IP SAN 10.99.0.254"),
        ):
            edge.render_bundle(
                services_path=self.services,
                certs_dir=self.certs,
                output_dir=self.output,
                caddy_binary=self.caddy,
            )

    def test_manifest_is_owner_only_and_contains_no_activation_command(self) -> None:
        self._render()
        manifest_path = self.output / "manifest.json"
        manifest = json.loads(manifest_path.read_text())

        self.assertEqual(oct(manifest_path.stat().st_mode & 0o777), "0o600")
        self.assertNotIn("launchctl", json.dumps(manifest))


if __name__ == "__main__":
    unittest.main()
