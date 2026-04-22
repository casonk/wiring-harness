#!/usr/bin/env python3
"""Render a local Markdown inventory of private browser/admin endpoints."""

from __future__ import annotations

import argparse
from pathlib import Path

from site_registry import DEFAULT_SERVICES_TOML, load_sites, render_inventory_markdown

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT = REPO_ROOT / "config" / "private-sites.inventory.local.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the merged private-site inventory from services.toml.",
    )
    parser.add_argument(
        "--services",
        default=str(DEFAULT_SERVICES_TOML),
        help=f"Path to services.toml (default: {DEFAULT_SERVICES_TOML})",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Markdown output path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args(argv)

    services_path = Path(args.services).expanduser().resolve()
    output_path = Path(args.output).expanduser()
    sites = load_sites(services_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_inventory_markdown(sites, services_path))
    print(f"wrote: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
