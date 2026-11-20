from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seal_pin_key.sh"

# A stand-in for systemd-creds so the script's own logic can run without a TPM or root.
FAKE = """#!/usr/bin/env bash
echo "$@" >> "$FAKE_LOG"
case "$1" in
  encrypt) cat > /dev/null; printf 'SEALED' > "${@: -1}" ;;
  decrypt) head -c "${FAKE_SIZE:-32}" /dev/zero ;;
esac
"""


class SealScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        fake = self.tmp / "bin" / "systemd-creds"
        fake.parent.mkdir()
        fake.write_text(FAKE)
        fake.chmod(0o755)
        self.log = self.tmp / "calls.log"
        # The script insists on root; run it through a copy that skips only that check.
        self.script = self.tmp / "seal.sh"
        text = SCRIPT.read_text().replace("[[ $EUID -eq 0 ]] ||", "[[ 1 -eq 1 ]] ||")
        self.script.write_text(text)
        self.out = self.tmp / "creds" / "key"

    def run_script(self, *args: str, size: str = "32") -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "PATH": f"{self.tmp / 'bin'}:{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            "FAKE_SIZE": size,
        }
        return subprocess.run(
            ["bash", str(self.script), "--output", str(self.out), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_syntax_is_valid(self) -> None:
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)], check=False).returncode, 0)

    def test_installs_a_tpm_bound_credential_with_the_expected_name_and_mode(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.out.exists())
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        encrypt = self.log.read_text().splitlines()[0]
        for part in ("--with-key=tpm2", "--tpm2-pcrs=7", "--name=pin-seal-key"):
            self.assertIn(part, encrypt)

    def test_refuses_to_replace_an_existing_key_without_force(self) -> None:
        self.assertEqual(self.run_script().returncode, 0)
        self.out.write_text("original")
        again = self.run_script()
        self.assertEqual(again.returncode, 1)
        self.assertEqual(self.out.read_text(), "original")
        self.assertEqual(self.run_script("--force").returncode, 0)
        self.assertEqual(self.out.read_text(), "SEALED")

    def test_installs_nothing_when_the_key_does_not_decrypt_to_32_bytes(self) -> None:
        result = self.run_script(size="5")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.out.exists())
        self.assertEqual([p.name for p in self.out.parent.iterdir()], [])  # no temp file left behind

    def test_never_prints_the_key(self) -> None:
        result = self.run_script()
        self.assertNotIn("\x00", result.stdout + result.stderr)
        self.assertIn("32 bytes", result.stdout)


if __name__ == "__main__":
    unittest.main()
