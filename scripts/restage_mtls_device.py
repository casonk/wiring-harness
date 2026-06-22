#!/usr/bin/env python3
"""Restage per-device mTLS artifacts without rotating the identity.

This wraps export_mtls_profile.py with the defaults needed for the common
support flow: reuse the existing per-device identity, rebuild the Apple profile,
and re-copy the staged pickup artifacts.

Examples:
    sudo python3 scripts/restage_mtls_device.py --device-name macbook-air
    sudo python3 scripts/restage_mtls_device.py --device-name macbook-air --show-passwords
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
EXPORT_SCRIPT = SCRIPT_DIR / "export_mtls_profile.py"
INSPECT_SCRIPT = SCRIPT_DIR / "inspect_mtls_device.py"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Restage per-device Apple profile and PKCS#12 artifacts without rotating the identity.",
    )
    parser.add_argument("--device-name", required=True, help="Device name, for example macbook-air")
    parser.add_argument("--devices", help="Path to devices.toml override")
    parser.add_argument(
        "--delivery",
        choices=["local-browser-install", "apple-profile"],
        help="Fallback delivery mode if device is not in devices.toml",
    )
    parser.add_argument(
        "--type",
        choices=["desktop", "mobile"],
        help="Legacy alias for --delivery if device is not in devices.toml",
    )
    parser.add_argument("--platform", help="Fallback platform if device is not in devices.toml")
    parser.add_argument("--ca-cert", help="CA certificate override")
    parser.add_argument("--ca-key", help="CA key override")
    parser.add_argument("--issued-dir", help="Issued identity directory override")
    parser.add_argument("--output", help="Override staged mobileconfig output path")
    parser.add_argument("--p12-output", help="Override staged PKCS#12 output path")
    parser.add_argument("--owner", help="Owner for staged files override")
    parser.add_argument("--group", help="Group for staged files override")
    parser.add_argument("--organization", help="Profile organization override")
    parser.add_argument("--profile-identifier-prefix", help="Profile identifier prefix override")
    parser.add_argument("--snowbridge-ca-cert", help="Snowbridge CA certificate override")
    parser.add_argument("--snowbridge-ca-key", help="Snowbridge CA key override")
    parser.add_argument("--snowbridge-issued-dir", help="Snowbridge issued directory override")
    parser.add_argument("--no-snowbridge", action="store_true", help="Skip the Snowbridge extra identity payload")
    parser.add_argument("--signing-cert", help="Signing certificate override")
    parser.add_argument("--signing-key", help="Signing key override")
    parser.add_argument("--no-sign", action="store_true", help="Skip CMS signing of the mobileconfig")
    parser.add_argument("--notify", action="store_true", help="Allow notifications during restage")
    parser.add_argument("--show-passwords", action="store_true", help="Inspect and print PKCS#12 passwords after restaging")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without changing the host")
    return parser


def append_opt(command: list[str], flag: str, value: str | None) -> None:
    if value:
        command.extend([flag, value])


def main() -> int:
    args = build_parser().parse_args()

    command = [sys.executable, str(EXPORT_SCRIPT), "--device-name", args.device_name]
    append_opt(command, "--devices", args.devices)
    append_opt(command, "--delivery", args.delivery)
    append_opt(command, "--type", args.type)
    append_opt(command, "--platform", args.platform)
    append_opt(command, "--ca-cert", args.ca_cert)
    append_opt(command, "--ca-key", args.ca_key)
    append_opt(command, "--issued-dir", args.issued_dir)
    append_opt(command, "--output", args.output)
    append_opt(command, "--p12-output", args.p12_output)
    append_opt(command, "--owner", args.owner)
    append_opt(command, "--group", args.group)
    append_opt(command, "--organization", args.organization)
    append_opt(command, "--profile-identifier-prefix", args.profile_identifier_prefix)
    append_opt(command, "--snowbridge-ca-cert", args.snowbridge_ca_cert)
    append_opt(command, "--snowbridge-ca-key", args.snowbridge_ca_key)
    append_opt(command, "--snowbridge-issued-dir", args.snowbridge_issued_dir)
    append_opt(command, "--signing-cert", args.signing_cert)
    append_opt(command, "--signing-key", args.signing_key)

    if args.no_snowbridge:
        command.append("--no-snowbridge")
    if args.no_sign:
        command.append("--no-sign")
    if args.dry_run:
        command.append("--dry-run")
    if not args.notify:
        command.append("--no-notify")

    print("==> Restaging device artifacts...")
    result = subprocess.run(command)
    if result.returncode != 0:
        return result.returncode

    if args.show_passwords:
        inspect_command = [sys.executable, str(INSPECT_SCRIPT), "--device-name", args.device_name, "--show-passwords"]
        append_opt(inspect_command, "--issued-dir", args.issued_dir)
        append_opt(inspect_command, "--snowbridge-issued-dir", args.snowbridge_issued_dir)
        if args.output:
            append_opt(inspect_command, "--share-tmp", str(Path(args.output).expanduser().resolve().parent))
        print("\n==> Inspecting restaged artifacts...")
        return subprocess.run(inspect_command).returncode

    print("\n==> Restage complete.")
    print("Run inspect_mtls_device.py if you need the verified import passwords or artifact paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
