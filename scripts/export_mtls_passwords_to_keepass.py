#!/usr/bin/env python3
"""Export p12 import passphrases for mobile mTLS configs into KeePass.

Reads each mobile device's passphrase from the issued certs directory and
upserts a KeePass entry at wiring-harness/mtls/<device-name>.  Also exports
the per-device snowbridge filebrowser client identity passphrase (stored
separately under the snowbridge issued dir) to snowbridge/mtls/<device-name>.

Usage:
    python3 scripts/export_mtls_passwords_to_keepass.py
    python3 scripts/export_mtls_passwords_to_keepass.py --dry-run
    python3 scripts/export_mtls_passwords_to_keepass.py --group certs/mtls
    python3 scripts/export_mtls_passwords_to_keepass.py --allow-interactive
    python3 scripts/export_mtls_passwords_to_keepass.py --no-snowbridge
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

_AUTO_PASS_SRC = REPO_ROOT.parent / "auto-pass" / "src"
if _AUTO_PASS_SRC.is_dir():
    sys.path.insert(0, str(_AUTO_PASS_SRC))

DEFAULT_DEVICES_TOML = REPO_ROOT / "devices.toml"
DEFAULT_ISSUED_DIR = Path("~/.config/wiring-harness/certs/issued")
DEFAULT_KEEPASS_GROUP = "wiring-harness/mtls"
SLUG_PREFIX = "wiring-harness-mtls"

DEFAULT_SNOWBRIDGE_ISSUED_DIR = Path("/var/lib/snowbridge/caddy/data/mtls/issued")
DEFAULT_SNOWBRIDGE_KEEPASS_GROUP = "snowbridge/mtls"
SNOWBRIDGE_SLUG_PREFIX = "snowbridge-caddy-mtls"


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")


def _load_mobile_device_names(devices_path: Path) -> list[str]:
    if not devices_path.exists():
        return []
    data = tomllib.loads(devices_path.read_text())
    local_path = devices_path.with_name(devices_path.stem + ".local.toml")
    if local_path.exists():
        local = tomllib.loads(local_path.read_text())
        local_by_name = {e["name"]: e for e in local.get("devices", [])}
        base_by_name = {e["name"]: e for e in data.get("devices", [])}
        for name, overrides in local_by_name.items():
            if name in base_by_name:
                base_by_name[name].update(overrides)
            else:
                data.setdefault("devices", []).append(overrides)
    return [
        e["name"]
        for e in data.get("devices", [])
        if e.get("type", "mobile") == "mobile"
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--devices",
        default=str(DEFAULT_DEVICES_TOML),
        metavar="PATH",
        help=f"Path to devices.toml (default: {DEFAULT_DEVICES_TOML})",
    )
    parser.add_argument(
        "--issued-dir",
        default=str(DEFAULT_ISSUED_DIR),
        metavar="PATH",
        help=f"Directory of issued identity files (default: {DEFAULT_ISSUED_DIR})",
    )
    parser.add_argument(
        "--group",
        default=DEFAULT_KEEPASS_GROUP,
        metavar="GROUP",
        help=f"KeePass group path prefix (default: {DEFAULT_KEEPASS_GROUP})",
    )
    parser.add_argument(
        "--allow-interactive",
        action="store_true",
        help="Prompt for KeePass database password if not set in the environment",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without touching KeePass",
    )
    parser.add_argument(
        "--keepass-profile",
        default="infra",
        metavar="PROFILE",
        help="auto-pass KeePass profile to use (default: infra)",
    )
    parser.add_argument(
        "--snowbridge-issued-dir",
        default=str(DEFAULT_SNOWBRIDGE_ISSUED_DIR),
        metavar="PATH",
        help=f"Directory of snowbridge-issued identity files (default: {DEFAULT_SNOWBRIDGE_ISSUED_DIR})",
    )
    parser.add_argument(
        "--snowbridge-group",
        default=DEFAULT_SNOWBRIDGE_KEEPASS_GROUP,
        metavar="GROUP",
        help=f"KeePass group path for snowbridge passwords (default: {DEFAULT_SNOWBRIDGE_KEEPASS_GROUP})",
    )
    parser.add_argument(
        "--no-snowbridge",
        action="store_true",
        help="Skip exporting snowbridge filebrowser client identity passwords",
    )
    args = parser.parse_args()

    issued_dir = Path(args.issued_dir).expanduser().resolve()
    devices_path = Path(args.devices)

    device_names = _load_mobile_device_names(devices_path)
    if not device_names:
        print("error: no mobile devices found in devices.toml", file=sys.stderr)
        return 1

    from auto_pass.envfile import load_config_environment  # noqa: PLC0415
    from auto_pass.keepassxc import ensure_group, upsert_keepassxc_entry  # noqa: PLC0415

    env_file = REPO_ROOT.parent / "auto-pass" / "config" / "auto-pass.env.local"
    if env_file.exists():
        load_config_environment(str(env_file))
    else:
        print(f"  note: env file not found at {env_file}, relying on environment variables")

    os.environ["AUTO_PASS_PROFILE"] = args.keepass_profile

    group = args.group.strip("/")
    errors: list[str] = []

    if not args.dry_run:
        parts = group.split("/")
        for i in range(1, len(parts) + 1):
            ensure_group(
                "/".join(parts[:i]),
                allow_interactive=args.allow_interactive,
            )

    for name in device_names:
        slug = _slugify(name)
        passphrase_path = issued_dir / f"{SLUG_PREFIX}-{slug}.passphrase"

        if not passphrase_path.exists():
            print(f"  skip {name}: passphrase file not found ({passphrase_path})")
            continue

        try:
            passphrase = passphrase_path.read_text(encoding="utf-8").strip()
        except PermissionError:
            print(
                f"  error: {name}: cannot read {passphrase_path} "
                "(root-owned — fix with: "
                f"sudo chown $USER {passphrase_path})",
                file=sys.stderr,
            )
            errors.append(name)
            continue
        if not passphrase:
            print(f"  skip {name}: passphrase file is empty ({passphrase_path})")
            continue

        entry = f"{group}/{name}"
        if args.dry_run:
            print(f"  dry-run: would upsert {entry!r}")
            continue

        try:
            mode = upsert_keepassxc_entry(
                entry,
                username=name,
                password=passphrase,
                notes="P12 import passphrase for wiring-harness mTLS mobile config.",
                allow_interactive=args.allow_interactive,
            )
            print(f"  {mode}: {entry}")
        except Exception as exc:
            print(f"  error: {name}: {exc}", file=sys.stderr)
            errors.append(name)

    if not args.no_snowbridge:
        sb_issued_dir = Path(args.snowbridge_issued_dir).expanduser().resolve()
        sb_group = args.snowbridge_group.strip("/")

        if not args.dry_run:
            parts = sb_group.split("/")
            for i in range(1, len(parts) + 1):
                ensure_group(
                    "/".join(parts[:i]),
                    allow_interactive=args.allow_interactive,
                )

        for name in device_names:
            slug = _slugify(name)
            passphrase_path = sb_issued_dir / f"{SNOWBRIDGE_SLUG_PREFIX}-{slug}.passphrase"

            if not passphrase_path.exists():
                print(f"  skip {name} (snowbridge): passphrase file not found ({passphrase_path})")
                continue

            try:
                passphrase = passphrase_path.read_text(encoding="utf-8").strip()
            except PermissionError:
                print(
                    f"  error: {name} (snowbridge): cannot read {passphrase_path} "
                    f"(run as root or fix ownership)",
                    file=sys.stderr,
                )
                errors.append(f"{name}/snowbridge")
                continue
            if not passphrase:
                print(f"  skip {name} (snowbridge): passphrase file is empty")
                continue

            entry = f"{sb_group}/{name}"
            if args.dry_run:
                print(f"  dry-run: would upsert {entry!r} (snowbridge)")
                continue

            try:
                mode = upsert_keepassxc_entry(
                    entry,
                    username=name,
                    password=passphrase,
                    notes="P12 import passphrase for snowbridge filebrowser mTLS mobile config.",
                    allow_interactive=args.allow_interactive,
                )
                print(f"  {mode}: {entry} (snowbridge)")
            except Exception as exc:
                print(f"  error: {name} (snowbridge): {exc}", file=sys.stderr)
                errors.append(f"{name}/snowbridge")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
