from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
SPEC = importlib.util.spec_from_file_location("setup_caddy", SCRIPTS_DIR / "setup_caddy.py")
assert SPEC is not None and SPEC.loader is not None
setup_caddy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup_caddy)


class CaddyUpstreamTests(unittest.TestCase):
    def test_unix_socket_renders_caddy_native_target(self) -> None:
        content = setup_caddy.generate_caddyfile(
            [
                {
                    "name": "nordility",
                    "hostname": "nordility.clockwork.internal",
                    "unix_socket": "/run/nordility/web.sock",
                }
            ],
            Path("/etc/caddy/certs/wiring-harness"),
            Path("/home/operator"),
        )

        self.assertIn("reverse_proxy unix//run/nordility/web.sock", content)
        self.assertNotIn("127.0.0.1", content)

    def test_unix_socket_and_port_fields_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be combined with port fields"):
            setup_caddy.generate_caddyfile(
                [
                    {
                        "name": "mixed",
                        "hostname": "mixed.internal",
                        "unix_socket": "/run/mixed.sock",
                        "port": 5300,
                    }
                ],
                Path("/certs"),
                Path("/home/operator"),
            )

    def test_unix_socket_must_be_canonical_and_injection_safe(self) -> None:
        invalid_paths = (
            "run/nordility/web.sock",
            "/run/nordility/../other.sock",
            "/run/nordility//web.sock",
            "/run/nordility/web.sock\nheader_up X-Bad true",
            "/run/{env.BAD}.sock",
            '/run/nordility/"quoted".sock',
            "/run/nordility/#comment.sock",
            "/",
        )
        for socket_path in invalid_paths:
            with self.subTest(socket_path=socket_path):
                with self.assertRaises(ValueError):
                    setup_caddy._resolve_proxy_target(
                        {"name": "unsafe", "unix_socket": socket_path},
                        Path("/home/operator"),
                    )

    def test_tcp_upstream_remains_compatible(self) -> None:
        target = setup_caddy._resolve_proxy_target(
            {"name": "clockwork", "port": 8788},
            Path("/home/operator"),
        )

        self.assertEqual(target, "127.0.0.1:8788")


class CaddyStaticRootTests(unittest.TestCase):
    def test_static_root_renders_file_server_with_index(self) -> None:
        content = setup_caddy.generate_caddyfile(
            [
                {
                    "name": "bench",
                    "hostname": "bench.home.internal",
                    "static_root": "/srv/bench/results",
                    "static_index": "latest.html",
                }
            ],
            Path("/etc/caddy/certs/wiring-harness"),
            Path("/home/operator"),
        )

        self.assertIn("root * /srv/bench/results", content)
        self.assertIn("file_server browse {\n\t\tindex latest.html\n\t}", content)
        self.assertIn("mode require_and_verify", content)
        self.assertNotIn("reverse_proxy", content)

    def test_static_root_rejects_upstream_fields(self) -> None:
        for field, value in (("port", 8080), ("unix_socket", "/run/x.sock"), ("proxy_headers", {"X": "y"})):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "cannot be combined with upstream fields"):
                    setup_caddy._resolve_static_root(
                        {"name": "mixed", "static_root": "/srv/site", field: value}
                    )

    def test_static_root_must_be_canonical_and_injection_safe(self) -> None:
        for root in ("srv/site", "/srv/../etc", "/srv//site", "/srv/site/", "/srv/{env.X}", "/srv/site\nimport x", "/"):
            with self.subTest(root=root):
                with self.assertRaises(ValueError):
                    setup_caddy._resolve_static_root({"name": "unsafe", "static_root": root})

    def test_static_index_must_be_a_plain_file_name(self) -> None:
        for index in ("../secret", "a/b.html", "x.html\nbrowse", ".hidden"):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    setup_caddy._resolve_static_index({"name": "bad", "static_index": index})


if __name__ == "__main__":
    unittest.main()
