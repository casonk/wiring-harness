from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "bootstrap_macos_air_pki.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_macos_air_pki", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
air_pki = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = air_pki
SPEC.loader.exec_module(air_pki)


class MacOSAirPkiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("OpenSSL is required")
        cls.openssl = Path(openssl).resolve()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.certs = self.root / "certs"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _bootstrap(self, **overrides: object) -> air_pki.BootstrapResult:
        options = {
            "certs_dir": self.certs,
            "openssl_binary": self.openssl,
            "wireguard_ip": "10.99.0.254",
        }
        options.update(overrides)
        return air_pki.bootstrap_pki(**options)

    def _generate_legacy_ca(self) -> Path:
        legacy = self.root / "legacy-clockwork-ca.crt"
        legacy_key = self.root / "legacy-clockwork-ca.key"
        subprocess.run(
            [
                str(self.openssl),
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-subj",
                "/CN=Legacy Clockwork CA/O=Portfolio",
                "-keyout",
                str(legacy_key),
                "-out",
                str(legacy),
            ],
            capture_output=True,
            check=True,
        )
        legacy_key.unlink()
        os.chmod(legacy, 0o644)
        return legacy

    def test_creates_owner_only_validated_air_material(self) -> None:
        result = self._bootstrap()

        self.assertFalse(result.idempotent)
        self.assertIsNone(result.backup_dir)
        self.assertEqual(stat.S_IMODE(self.certs.stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in self.certs.iterdir()), sorted(air_pki.REQUIRED_FILES))
        for path in self.certs.iterdir():
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        self.assertNotIn(b"PRIVATE KEY", self.certs.joinpath("ca.crt").read_bytes())
        self.assertEqual(self.certs.joinpath("ca.crt").read_bytes().count(air_pki.CERTIFICATE_BEGIN), 1)

    def test_second_run_is_idempotent_and_does_not_replace_keys(self) -> None:
        self._bootstrap()
        original_key = self.certs.joinpath("air-ca.key").read_bytes()

        result = self._bootstrap()

        self.assertTrue(result.idempotent)
        self.assertEqual(self.certs.joinpath("air-ca.key").read_bytes(), original_key)
        self.assertFalse(any(self.root.glob("certs.backup-*")))

    def test_accepts_a_trusted_package_manager_openssl_symlink(self) -> None:
        openssl_link = self.root / "openssl"
        openssl_link.symlink_to(self.openssl)

        result = self._bootstrap(openssl_binary=openssl_link)

        self.assertFalse(result.idempotent)

    def test_refuses_partial_existing_state_without_rotate(self) -> None:
        self.certs.mkdir(mode=0o700)
        partial = self.certs / "air-ca.key"
        partial.write_text("not a key\n", encoding="utf-8")
        os.chmod(partial, 0o600)

        with self.assertRaisesRegex(air_pki.BootstrapError, "refusing to overwrite"):
            self._bootstrap()

        self.assertEqual(partial.read_text(encoding="utf-8"), "not a key\n")

    def test_refuses_group_readable_extra_material(self) -> None:
        self._bootstrap()
        extra = self.certs / "unmanaged.crt"
        extra.write_text("public but unmanaged\n", encoding="utf-8")
        os.chmod(extra, 0o644)

        with self.assertRaisesRegex(air_pki.BootstrapError, "refusing to overwrite"):
            self._bootstrap()
        with self.assertRaisesRegex(air_pki.BootstrapError, "unsafe PKI entry"):
            self._bootstrap(rotate=True)

    def test_explicit_rotate_retains_owner_only_backup(self) -> None:
        self._bootstrap()
        original_key = self.certs.joinpath("air-ca.key").read_bytes()

        result = self._bootstrap(rotate=True)

        self.assertFalse(result.idempotent)
        self.assertIsNotNone(result.backup_dir)
        assert result.backup_dir is not None
        self.assertTrue(result.backup_dir.is_dir())
        self.assertEqual(stat.S_IMODE(result.backup_dir.stat().st_mode), 0o700)
        self.assertEqual(result.backup_dir.joinpath("air-ca.key").read_bytes(), original_key)
        self.assertNotEqual(self.certs.joinpath("air-ca.key").read_bytes(), original_key)

    def test_failed_post_install_rotation_restores_previous_directory(self) -> None:
        self._bootstrap()
        original_key = self.certs.joinpath("air-ca.key").read_bytes()
        original_validate = air_pki.validate_pki

        def fail_only_after_install(**arguments: object) -> None:
            candidate = Path(arguments["certs_dir"])
            if candidate.resolve() == self.certs.resolve():
                raise air_pki.BootstrapError("injected post-install validation failure")
            original_validate(**arguments)

        with (
            mock.patch.object(air_pki, "validate_pki", side_effect=fail_only_after_install),
            self.assertRaisesRegex(air_pki.BootstrapError, "injected post-install"),
        ):
            self._bootstrap(rotate=True)

        self.assertEqual(self.certs.joinpath("air-ca.key").read_bytes(), original_key)
        self.assertFalse(any(self.root.glob("certs.backup-*")))
        self.assertFalse(any(self.root.glob(".certs.staging-*")))

    def test_optional_legacy_public_ca_is_appended_without_private_material(self) -> None:
        legacy = self._generate_legacy_ca()

        self._bootstrap(legacy_client_ca=legacy)

        trust_bundle = self.certs.joinpath("ca.crt").read_bytes()
        self.assertEqual(trust_bundle.count(air_pki.CERTIFICATE_BEGIN), 2)
        self.assertNotIn(b"PRIVATE KEY", trust_bundle)

    def test_rejects_legacy_input_containing_private_key_material(self) -> None:
        legacy = self._generate_legacy_ca()
        private_key_marker = air_pki.PEM_BEGIN + b"PRIVATE KEY-----\nunsafe\n-----END PRIVATE KEY-----\n"
        legacy.write_bytes(legacy.read_bytes() + private_key_marker)

        with self.assertRaisesRegex(air_pki.BootstrapError, "must not contain private-key"):
            self._bootstrap(legacy_client_ca=legacy)

    def test_validation_detects_a_mismatched_private_key(self) -> None:
        self._bootstrap()
        self.certs.joinpath("client.key").write_bytes(self.certs.joinpath("server.key").read_bytes())
        os.chmod(self.certs / "client.key", 0o600)

        with self.assertRaisesRegex(air_pki.BootstrapError, "do not match"):
            air_pki.validate_pki(
                certs_dir=self.certs,
                openssl_binary=self.openssl,
                wireguard_ip=air_pki._validate_private_ipv4("10.99.0.254"),
                legacy_client_ca=None,
            )

    def test_rejects_public_or_non_ipv4_listener_address(self) -> None:
        for address in ("203.0.113.8", "2001:db8::1"):
            with self.subTest(address=address), self.assertRaisesRegex(air_pki.BootstrapError, "RFC1918 IPv4"):
                self._bootstrap(wireguard_ip=address)

    def test_cli_output_never_contains_private_key_material(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = air_pki.main(
                [
                    "--certs-dir",
                    str(self.certs),
                    "--openssl",
                    str(self.openssl),
                ]
            )

        self.assertEqual(status, 0, stderr.getvalue())
        output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("BEGIN " + "PRIVATE KEY", output)
        self.assertNotIn("PRIVATE KEY-----", output)
        self.assertNotIn(self.certs.joinpath("air-ca.key").read_text(encoding="utf-8").strip(), output)

    def test_openssl_calls_do_not_use_a_shell(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertNotIn("shell=True", source)
        self.assertNotIn("shell = True", source)
        self.assertNotIn("<(printf", source)


if __name__ == "__main__":
    unittest.main()
