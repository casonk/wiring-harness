#!/usr/bin/env python3
"""Inspect per-device mTLS artifacts and validate PKCS#12 passwords.

Examples:
    python3 scripts/inspect_mtls_device.py --device-name macbook-air
    sudo python3 scripts/inspect_mtls_device.py --device-name macbook-air --show-passwords
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from export_mtls_profile import (  # noqa: E402
    DEFAULT_SHARE_TMP,
    SLUG_PREFIX,
    SNOWBRIDGE_ISSUED_DIR,
    SNOWBRIDGE_SLUG_PREFIX,
    slugify,
)


def invoking_user_home() -> Path:
    sudo_user = subprocess.run(
        ["sh", "-c", "printf '%s' \"${SUDO_USER:-${USER}}\""],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return Path("~" + sudo_user).expanduser()


DEFAULT_ISSUED_DIR = invoking_user_home() / ".config" / "wiring-harness" / "certs" / "issued"


@dataclass
class IdentityArtifact:
    label: str
    p12_path: Path
    passphrase_path: Path


def verify_p12_password(p12_path: Path, passphrase_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        [
            "openssl",
            "pkcs12",
            "-info",
            "-in",
            str(p12_path),
            "-passin",
            f"file:{passphrase_path}",
            "-noout",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True, "ok"
    detail = (result.stderr or result.stdout).strip().splitlines()
    return False, detail[-1] if detail else "openssl pkcs12 verification failed"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect per-device mTLS artifacts and validate PKCS#12 passwords.",
    )
    parser.add_argument("--device-name", required=True, help="Device name, for example macbook-air")
    parser.add_argument(
        "--issued-dir",
        default=str(DEFAULT_ISSUED_DIR),
        help=f"Directory for wiring-harness issued identities (default: {DEFAULT_ISSUED_DIR})",
    )
    parser.add_argument(
        "--snowbridge-issued-dir",
        default=str(SNOWBRIDGE_ISSUED_DIR),
        help=f"Directory for snowbridge issued identities (default: {SNOWBRIDGE_ISSUED_DIR})",
    )
    parser.add_argument(
        "--share-tmp",
        default=str(DEFAULT_SHARE_TMP),
        help=f"Directory where staged mobile artifacts are written (default: {DEFAULT_SHARE_TMP})",
    )
    parser.add_argument(
        "--show-passwords",
        action="store_true",
        help="Print PKCS#12 import passwords in cleartext.",
    )
    return parser


def print_identity(identity: IdentityArtifact, *, show_passwords: bool) -> None:
    print(f"{identity.label}:")
    print(f"  p12: {identity.p12_path}")
    print(f"  passphrase file: {identity.passphrase_path}")
    if not identity.p12_path.exists():
        print("  status: missing .p12 file")
        return
    if not identity.passphrase_path.exists():
        print("  status: missing passphrase file")
        return
    ok, detail = verify_p12_password(identity.p12_path, identity.passphrase_path)
    if ok:
        print("  status: passphrase verified")
    else:
        print(f"  status: verification failed ({detail})")
        return
    if show_passwords:
        print(f"  import password: {identity.passphrase_path.read_text(encoding='utf-8').strip()}")


def main() -> int:
    args = build_parser().parse_args()

    slug = slugify(args.device_name)
    issued_dir = Path(args.issued_dir).expanduser().resolve()
    snowbridge_issued_dir = Path(args.snowbridge_issued_dir).expanduser().resolve()
    share_tmp = Path(args.share_tmp).expanduser().resolve()

    staged_mobileconfig = share_tmp / f"{SLUG_PREFIX}-{slug}.mobileconfig"
    staged_p12 = share_tmp / f"{SLUG_PREFIX}-{slug}.p12"
    staged_snowbridge_p12 = share_tmp / f"{SNOWBRIDGE_SLUG_PREFIX}-{slug}.p12"

    wiring = IdentityArtifact(
        label="wiring-harness identity",
        p12_path=issued_dir / f"{SLUG_PREFIX}-{slug}.p12",
        passphrase_path=issued_dir / f"{SLUG_PREFIX}-{slug}.passphrase",
    )
    snowbridge = IdentityArtifact(
        label="snowbridge identity",
        p12_path=snowbridge_issued_dir / f"{SNOWBRIDGE_SLUG_PREFIX}-{slug}.p12",
        passphrase_path=snowbridge_issued_dir / f"{SNOWBRIDGE_SLUG_PREFIX}-{slug}.passphrase",
    )

    print(f"device: {args.device_name}")
    print(f"slug: {slug}")
    print(f"staged mobileconfig: {staged_mobileconfig}")
    print(f"staged p12: {staged_p12}")
    print(f"staged snowbridge p12: {staged_snowbridge_p12}")
    print(f"staged mobileconfig exists: {'yes' if staged_mobileconfig.exists() else 'no'}")
    print(f"staged p12 exists: {'yes' if staged_p12.exists() else 'no'}")
    print(f"staged snowbridge p12 exists: {'yes' if staged_snowbridge_p12.exists() else 'no'}")
    print()

    print_identity(wiring, show_passwords=args.show_passwords)
    print()
    print_identity(snowbridge, show_passwords=args.show_passwords)
    print()
    print("macOS note:")
    print("  PKCS#12 import prompts use the identity-specific import password above.")
    print("  Keychain or profile-approval prompts use the Mac's local login/admin password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
