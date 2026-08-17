from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

SCRIPT_PATH = SCRIPTS_DIR / "export_macos_air_profiles.py"
SPEC = importlib.util.spec_from_file_location("export_macos_air_profiles", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
profiles = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profiles
SPEC.loader.exec_module(profiles)


class MacOSAirProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("OpenSSL is required")
        cls.openssl = Path(openssl).resolve()
        cls.fixture_temporary = tempfile.TemporaryDirectory()
        cls.fixture_root = Path(cls.fixture_temporary.name)
        cls.fixture_certs = cls.fixture_root / "certs"
        profiles.air_pki.bootstrap_pki(
            certs_dir=cls.fixture_certs,
            openssl_binary=cls.openssl,
            wireguard_ip="10.99.0.254",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.certs = self.root / "certs"
        shutil.copytree(self.fixture_certs, self.certs)
        self.output = self.root / "air-profiles"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _generate(self, **overrides: object) -> profiles.ProfileResult:
        options = {
            "certs_dir": self.certs,
            "output_root": self.output,
            "openssl_binary": self.openssl,
        }
        options.update(overrides)
        return profiles.generate_profiles(**options)

    def _identity(self, slug: str) -> Path:
        return self.output / profiles.IDENTITIES_DIR_NAME / slug

    def _profile(self, slug: str) -> Path:
        return self.output / profiles.PROFILES_DIR_NAME / profiles.DEVICES[slug].profile_file

    def _profile_plist(self, slug: str) -> dict:
        return plistlib.loads(self._profile(slug).read_bytes())

    def _snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.output)): path.read_bytes() for path in self.output.rglob("*") if path.is_file()
        }

    def test_creates_distinct_owner_only_mini_and_pro_profiles(self) -> None:
        result = self._generate()

        self.assertFalse(result.idempotent)
        self.assertEqual(result.generated_devices, ("mini", "pro"))
        self.assertEqual(
            {path.name for path in (self.output / profiles.PROFILES_DIR_NAME).iterdir()},
            {profiles.DEVICES[slug].profile_file for slug in ("mini", "pro")},
        )
        for path in self.output.rglob("*"):
            expected_mode = 0o700 if path.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected_mode, path)

        certificate_digests = set()
        profile_uuids = set()
        for slug in ("mini", "pro"):
            identity = self._identity(slug)
            certificate_der = profiles._certificate_der(self.openssl, identity / "client.crt")
            certificate_digests.add(profiles._sha256(certificate_der))
            profile = self._profile_plist(slug)
            profile_uuids.add(profile["PayloadUUID"])
            payloads = {payload["PayloadType"]: payload for payload in profile["PayloadContent"]}
            self.assertEqual(set(payloads), {"com.apple.security.root", "com.apple.security.pkcs12"})
            pkcs12_payload = payloads["com.apple.security.pkcs12"]
            self.assertFalse({"Password", "PayloadPassword"}.intersection(pkcs12_payload))
            passphrase = (identity / "client.p12.passphrase").read_text(encoding="ascii").strip()
            self.assertNotIn(passphrase.encode("ascii"), self._profile(slug).read_bytes())
            subprocess.run(
                [
                    str(self.openssl),
                    "verify",
                    "-CAfile",
                    str(self.certs / "air-ca.crt"),
                    "-purpose",
                    "sslclient",
                    str(identity / "client.crt"),
                ],
                check=True,
                capture_output=True,
            )
        self.assertEqual(len(certificate_digests), 2)
        self.assertEqual(len(profile_uuids), 2)
        self.assertFalse(json.loads((self.output / "manifest.json").read_text())["installation_performed"])

    def test_second_run_is_byte_idempotent(self) -> None:
        self._generate()
        before = self._snapshot()

        result = self._generate()

        self.assertTrue(result.idempotent)
        self.assertEqual(self._snapshot(), before)
        self.assertFalse(any(self.root.glob("air-profiles.backup-*")))

    def test_adding_pro_preserves_existing_mini_identity(self) -> None:
        self._generate(devices=("mini",))
        mini_key = (self._identity("mini") / "client.key").read_bytes()
        mini_profile = self._profile("mini").read_bytes()

        result = self._generate()

        self.assertEqual(result.generated_devices, ("pro",))
        self.assertEqual(result.preserved_devices, ("mini",))
        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), mini_key)
        self.assertEqual(self._profile("mini").read_bytes(), mini_profile)

    def test_partial_state_fails_closed_even_when_rotation_is_requested(self) -> None:
        self._generate()
        old_mini_key = (self._identity("mini") / "client.key").read_bytes()
        (self._identity("pro") / "client.p12").unlink()

        with self.assertRaisesRegex(profiles.ProfileError, "incomplete"):
            self._generate()
        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), old_mini_key)

        with self.assertRaisesRegex(profiles.ProfileError, "incomplete"):
            self._generate(rotate=True)
        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), old_mini_key)
        self.assertFalse(any(self.root.glob("air-profiles.backup-*")))

    def test_rotating_only_pro_preserves_mini_and_stable_profile_uuids(self) -> None:
        self._generate()
        mini_key = (self._identity("mini") / "client.key").read_bytes()
        pro_key = (self._identity("pro") / "client.key").read_bytes()
        before_uuids = {
            slug: [self._profile_plist(slug)["PayloadUUID"]]
            + [payload["PayloadUUID"] for payload in self._profile_plist(slug)["PayloadContent"]]
            for slug in ("mini", "pro")
        }

        self._generate(devices=("pro",), rotate=True)

        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), mini_key)
        self.assertNotEqual((self._identity("pro") / "client.key").read_bytes(), pro_key)
        after_uuids = {
            slug: [self._profile_plist(slug)["PayloadUUID"]]
            + [payload["PayloadUUID"] for payload in self._profile_plist(slug)["PayloadContent"]]
            for slug in ("mini", "pro")
        }
        self.assertEqual(after_uuids, before_uuids)

    def test_air_ca_rotation_requires_explicit_device_rotation(self) -> None:
        self._generate()
        profiles.air_pki.bootstrap_pki(
            certs_dir=self.certs,
            openssl_binary=self.openssl,
            wireguard_ip="10.99.0.254",
            rotate=True,
        )

        with self.assertRaisesRegex(profiles.ProfileError, "Air CA changed"):
            self._generate()

        self._generate(rotate=True)
        profiles.validate_profile_set(
            output_root=self.output,
            openssl_binary=self.openssl,
            ca_cert=self.certs / "air-ca.crt",
        )

    def test_cert_only_pkcs12_is_rejected_before_manifest_checks(self) -> None:
        self._generate()
        identity = self._identity("mini")
        subprocess.run(
            [
                str(self.openssl),
                "pkcs12",
                "-export",
                "-nokeys",
                "-in",
                str(identity / "client.crt"),
                "-certfile",
                str(self.certs / "air-ca.crt"),
                "-out",
                str(identity / "client.p12"),
                "-passout",
                f"file:{identity / 'client.p12.passphrase'}",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(identity / "client.p12", 0o600)

        with self.assertRaisesRegex(profiles.ProfileError, "exactly one private key"):
            profiles.validate_profile_set(
                output_root=self.output,
                openssl_binary=self.openssl,
                ca_cert=self.certs / "air-ca.crt",
            )

    def test_pkcs12_private_key_must_match_its_client_certificate(self) -> None:
        self._generate()
        mini_p12 = self._identity("mini") / "client.p12"
        pro_private_key = (self._identity("pro") / "client.key").read_bytes()
        real_openssl = profiles.air_pki._openssl

        def mismatched_key(binary: Path, *arguments: object, **options: object) -> subprocess.CompletedProcess:
            if (
                arguments[:1] == ("pkcs12",)
                and "-nocerts" in arguments
                and "-nodes" in arguments
                and "-in" in arguments
                and Path(arguments[arguments.index("-in") + 1]).resolve() == mini_p12.resolve()
            ):
                return subprocess.CompletedProcess(
                    [str(binary), *map(str, arguments)],
                    0,
                    pro_private_key,
                    b"",
                )
            return real_openssl(binary, *arguments, **options)

        with (
            mock.patch.object(profiles.air_pki, "_openssl", side_effect=mismatched_key),
            self.assertRaisesRegex(profiles.ProfileError, "private key does not match client.crt"),
        ):
            profiles.validate_profile_set(
                output_root=self.output,
                openssl_binary=self.openssl,
                ca_cert=self.certs / "air-ca.crt",
            )

    def test_live_trust_bundle_must_contain_exactly_one_air_root(self) -> None:
        air_ca = (self.certs / "air-ca.crt").read_bytes()

        (self.certs / "ca.crt").write_bytes((self.certs / "server.crt").read_bytes())
        os.chmod(self.certs / "ca.crt", 0o600)
        with self.assertRaisesRegex(profiles.ProfileError, "exact Air CA exactly once"):
            self._generate()
        self.assertFalse(self.output.exists())

        (self.certs / "ca.crt").write_bytes(air_ca + air_ca)
        os.chmod(self.certs / "ca.crt", 0o600)
        with self.assertRaisesRegex(profiles.ProfileError, "exact Air CA exactly once"):
            self._generate()
        self.assertFalse(self.output.exists())

    def test_live_trust_bundle_allows_a_distinct_legacy_root(self) -> None:
        legacy_certs = self.root / "legacy-certs"
        profiles.air_pki.bootstrap_pki(
            certs_dir=legacy_certs,
            openssl_binary=self.openssl,
            wireguard_ip="10.99.0.253",
        )
        bundle = (self.certs / "air-ca.crt").read_bytes() + (legacy_certs / "air-ca.crt").read_bytes()
        (self.certs / "ca.crt").write_bytes(bundle)
        os.chmod(self.certs / "ca.crt", 0o600)

        self._generate()

        for slug in ("mini", "pro"):
            subprocess.run(
                [
                    str(self.openssl),
                    "verify",
                    "-CAfile",
                    str(self.certs / "ca.crt"),
                    "-purpose",
                    "sslclient",
                    str(self._identity(slug) / "client.crt"),
                ],
                check=True,
                capture_output=True,
            )

    def test_rotation_renews_only_the_selected_near_expiry_identity(self) -> None:
        self._generate()
        before = self._snapshot()
        old_mini_key = (self._identity("mini") / "client.key").read_bytes()
        old_mini_profile = self._profile("mini").read_bytes()
        old_pro_certificate = (self._identity("pro") / "client.crt").read_bytes()
        real_openssl = profiles.air_pki._openssl

        def near_expiry(binary: Path, *arguments: object, **options: object) -> subprocess.CompletedProcess:
            try:
                cert_index = arguments.index("-in") + 1
                certificate = Path(arguments[cert_index])
            except (ValueError, IndexError, TypeError):
                certificate = None
            if (
                certificate is not None
                and certificate.is_file()
                and certificate.read_bytes() == old_pro_certificate
                and arguments[:1] == ("x509",)
                and "-checkend" in arguments
            ):
                return subprocess.CompletedProcess([str(binary), *map(str, arguments)], 1, b"", b"")
            return real_openssl(binary, *arguments, **options)

        with mock.patch.object(profiles.air_pki, "_openssl", side_effect=near_expiry):
            with self.assertRaisesRegex(profiles.ProfileError, "Pro certificate is expired or too close"):
                self._generate(devices=("mini",), rotate=True)
            self.assertEqual(self._snapshot(), before)

            result = self._generate(devices=("pro",), rotate=True)

        self.assertEqual(result.generated_devices, ("pro",))
        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), old_mini_key)
        self.assertEqual(self._profile("mini").read_bytes(), old_mini_profile)
        self.assertNotEqual((self._identity("pro") / "client.crt").read_bytes(), old_pro_certificate)
        profiles.validate_profile_set(
            output_root=self.output,
            openssl_binary=self.openssl,
            ca_cert=self.certs / "air-ca.crt",
        )

    def test_rotation_can_replace_an_expired_selected_identity(self) -> None:
        self._generate()
        old_mini_key = (self._identity("mini") / "client.key").read_bytes()
        old_mini_profile = self._profile("mini").read_bytes()
        old_pro_certificate = (self._identity("pro") / "client.crt").read_bytes()
        real_metadata = profiles._certificate_metadata
        real_openssl = profiles.air_pki._openssl
        metadata_calls = 0
        no_time_verification_seen = False

        def expired_metadata(binary: Path, certificate: Path) -> dict[str, str]:
            nonlocal metadata_calls
            result = real_metadata(binary, certificate)
            if certificate.read_bytes() == old_pro_certificate:
                metadata_calls += 1
                if metadata_calls == 1:
                    result = dict(result)
                    result["notBefore"] = "Jan  1 00:00:00 2020 GMT"
                    result["notAfter"] = "Jan  2 00:00:00 2020 GMT"
            return result

        def expired_openssl(binary: Path, *arguments: object, **options: object) -> subprocess.CompletedProcess:
            nonlocal no_time_verification_seen
            certificate: Path | None = None
            if arguments[:1] == ("x509",) and "-in" in arguments:
                candidate = arguments[arguments.index("-in") + 1]
                if isinstance(candidate, str | Path):
                    candidate_path = Path(candidate)
                    if candidate_path.is_file():
                        certificate = candidate_path
            elif arguments:
                candidate = arguments[-1]
                if isinstance(candidate, str | Path):
                    candidate_path = Path(candidate)
                    if candidate_path.is_file():
                        certificate = candidate_path
            is_old_pro = certificate is not None and certificate.read_bytes() == old_pro_certificate
            if is_old_pro and arguments[:1] == ("x509",) and "-checkend" in arguments:
                return subprocess.CompletedProcess([str(binary), *map(str, arguments)], 1, b"", b"")
            if is_old_pro and arguments[:1] == ("verify",) and "-purpose" in arguments:
                purpose = arguments[arguments.index("-purpose") + 1]
                if purpose == "sslclient" and "-no_check_time" not in arguments:
                    return subprocess.CompletedProcess([str(binary), *map(str, arguments)], 2, b"", b"")
                if purpose == "sslclient" and "-no_check_time" in arguments:
                    no_time_verification_seen = True
            return real_openssl(binary, *arguments, **options)

        with (
            mock.patch.object(profiles, "_certificate_metadata", side_effect=expired_metadata),
            mock.patch.object(profiles.air_pki, "_openssl", side_effect=expired_openssl),
        ):
            result = self._generate(devices=("pro",), rotate=True)

        self.assertEqual(result.generated_devices, ("pro",))
        self.assertTrue(no_time_verification_seen)
        self.assertEqual((self._identity("mini") / "client.key").read_bytes(), old_mini_key)
        self.assertEqual(self._profile("mini").read_bytes(), old_mini_profile)
        self.assertNotEqual((self._identity("pro") / "client.crt").read_bytes(), old_pro_certificate)
        profiles.validate_profile_set(
            output_root=self.output,
            openssl_binary=self.openssl,
            ca_cert=self.certs / "air-ca.crt",
        )

    def test_failed_post_install_validation_restores_previous_profile_set(self) -> None:
        self._generate()
        original = self._snapshot()
        real_validate = profiles.validate_profile_set

        def fail_after_install(**arguments: object) -> dict:
            candidate = Path(arguments["output_root"])
            if candidate.resolve() == self.output.resolve():
                raise profiles.ProfileError("injected post-install validation failure")
            return real_validate(**arguments)

        with (
            mock.patch.object(profiles, "validate_profile_set", side_effect=fail_after_install),
            self.assertRaisesRegex(profiles.ProfileError, "injected post-install"),
        ):
            self._generate(devices=("pro",), rotate=True)

        self.assertEqual(self._snapshot(), original)
        self.assertFalse(any(self.root.glob(".air-profiles.staging-*")))

    def test_copy_passphrase_validates_then_writes_only_to_pbcopy_stdin(self) -> None:
        self._generate()
        passphrase = (self._identity("mini") / "client.p12.passphrase").read_text(encoding="ascii").strip()
        completed = subprocess.CompletedProcess(["/usr/bin/pbcopy"], 0, stdout=b"", stderr=b"")
        stdout = io.StringIO()
        with (
            mock.patch.object(profiles, "_resolve_pbcopy", return_value=Path("/usr/bin/pbcopy")),
            mock.patch.object(profiles, "_run_pbcopy", return_value=completed) as run,
            contextlib.redirect_stdout(stdout),
        ):
            profiles.copy_passphrase(
                device="mini",
                certs_dir=self.certs,
                output_root=self.output,
                openssl_binary=self.openssl,
            )

        self.assertEqual(stdout.getvalue(), "")
        run.assert_called_once_with(["/usr/bin/pbcopy"], passphrase.encode("ascii"))

    def test_safe_finder_metadata_does_not_block_validation_or_clipboard(self) -> None:
        self._generate()
        for directory in (
            self.output,
            self.output / profiles.PROFILES_DIR_NAME,
        ):
            metadata = directory / profiles.FINDER_METADATA_NAME
            metadata.write_bytes(b"Finder metadata")
            os.chmod(metadata, 0o644)

        result = self._generate()
        self.assertTrue(result.idempotent)

        completed = subprocess.CompletedProcess(["/usr/bin/pbcopy"], 0, stdout=b"", stderr=b"")
        with (
            mock.patch.object(profiles, "_resolve_pbcopy", return_value=Path("/usr/bin/pbcopy")),
            mock.patch.object(profiles, "_run_pbcopy", return_value=completed) as run,
        ):
            profiles.copy_passphrase(
                device="pro",
                certs_dir=self.certs,
                output_root=self.output,
                openssl_binary=self.openssl,
            )
        run.assert_called_once()

    def test_unsafe_finder_metadata_and_near_matches_still_fail_closed(self) -> None:
        self._generate()
        metadata = self.output / profiles.FINDER_METADATA_NAME
        metadata.write_bytes(b"Finder metadata")
        os.chmod(metadata, 0o666)
        with (
            mock.patch.object(profiles, "_run_pbcopy") as run,
            self.assertRaisesRegex(profiles.ProfileError, "unsafe Finder metadata"),
        ):
            profiles.copy_passphrase(
                device="pro",
                certs_dir=self.certs,
                output_root=self.output,
                openssl_binary=self.openssl,
            )
        run.assert_not_called()

        metadata.unlink()
        metadata.symlink_to(self.output / profiles.ROOT_MANIFEST_NAME)
        with self.assertRaisesRegex(profiles.ProfileError, "unsafe Finder metadata"):
            self._generate()

        metadata.unlink()
        near_match = self.output / ".DS_Store.tmp"
        near_match.write_bytes(b"not allowlisted")
        os.chmod(near_match, 0o600)
        with self.assertRaisesRegex(profiles.ProfileError, "unexpected entry"):
            self._generate()

        near_match.unlink()
        identity_metadata = self._identity("mini") / profiles.FINDER_METADATA_NAME
        identity_metadata.write_bytes(b"Finder metadata is not allowed in identity state")
        os.chmod(identity_metadata, 0o644)
        with self.assertRaisesRegex(profiles.ProfileError, "unsafe profile entry"):
            self._generate()

        os.chmod(identity_metadata, 0o600)
        with self.assertRaisesRegex(profiles.ProfileError, "unexpected artifacts"):
            self._generate()

    def test_hardlinked_and_nonregular_finder_metadata_fail_closed(self) -> None:
        self._generate()
        source = self.root / "finder-metadata-source"
        source.write_bytes(b"Finder metadata")
        os.chmod(source, 0o644)
        metadata = self.output / profiles.FINDER_METADATA_NAME
        os.link(source, metadata)
        with self.assertRaisesRegex(profiles.ProfileError, "unsafe Finder metadata"):
            self._generate()

        metadata.unlink()
        os.mkfifo(metadata, 0o600)
        with self.assertRaisesRegex(profiles.ProfileError, "unsafe Finder metadata"):
            self._generate()

    def test_finder_metadata_remains_forbidden_in_the_source_pki(self) -> None:
        self._generate()
        metadata = self.certs / profiles.FINDER_METADATA_NAME
        metadata.write_bytes(b"Finder metadata")
        os.chmod(metadata, 0o644)

        with self.assertRaisesRegex(profiles.ProfileError, "unsafe PKI entry"):
            self._generate()

    def test_rotation_does_not_copy_finder_metadata_into_the_new_profile_set(self) -> None:
        self._generate()
        for directory in (
            self.output,
            self.output / profiles.PROFILES_DIR_NAME,
        ):
            metadata = directory / profiles.FINDER_METADATA_NAME
            metadata.write_bytes(b"Finder metadata")
            os.chmod(metadata, 0o644)

        result = self._generate(devices=("pro",), rotate=True)

        self.assertIsNotNone(result.backup_dir)
        assert result.backup_dir is not None
        self.assertTrue((result.backup_dir / profiles.FINDER_METADATA_NAME).is_file())
        self.assertTrue((result.backup_dir / profiles.PROFILES_DIR_NAME / profiles.FINDER_METADATA_NAME).is_file())
        self.assertFalse(any(path.name == profiles.FINDER_METADATA_NAME for path in self.output.rglob("*")))

    def test_invalid_state_never_reaches_pbcopy(self) -> None:
        self._generate()
        (self._identity("mini") / "manifest.json").write_text("{}\n", encoding="utf-8")
        os.chmod(self._identity("mini") / "manifest.json", 0o600)

        with (
            mock.patch.object(profiles, "_run_pbcopy") as run,
            self.assertRaisesRegex(profiles.ProfileError, "manifest"),
        ):
            profiles.copy_passphrase(
                device="mini",
                certs_dir=self.certs,
                output_root=self.output,
                openssl_binary=self.openssl,
            )
        run.assert_not_called()

    def test_cli_never_prints_private_material_or_passphrases(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = profiles.main(
                [
                    "--certs-dir",
                    str(self.certs),
                    "--output-root",
                    str(self.output),
                    "--openssl",
                    str(self.openssl),
                ]
            )

        self.assertEqual(status, 0, stderr.getvalue())
        output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("PRIVATE KEY-----", output)
        for slug in ("mini", "pro"):
            passphrase = (self._identity(slug) / "client.p12.passphrase").read_text(encoding="ascii").strip()
            self.assertNotIn(passphrase, output)

    def test_openssl_and_clipboard_calls_never_use_a_shell(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertNotIn("shell=True", source)
        self.assertNotIn("shell = True", source)


if __name__ == "__main__":
    unittest.main()
