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


if __name__ == "__main__":
    unittest.main()
