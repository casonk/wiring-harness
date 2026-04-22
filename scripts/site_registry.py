#!/usr/bin/env python3
"""Helpers for the private site registry stored in services.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SERVICES_TOML = REPO_ROOT / "services.toml"


def load_services_data(services_path: Path = DEFAULT_SERVICES_TOML) -> dict:
    """Load services.toml and merge services.local.toml overrides if present."""
    data = tomllib.loads(services_path.read_text())
    local_path = services_path.with_name(services_path.stem + ".local.toml")
    if not local_path.exists():
        return data

    local = tomllib.loads(local_path.read_text())
    for key, value in local.items():
        if key != "services":
            data[key] = value

    local_by_name = {service["name"]: service for service in local.get("services", [])}
    base_by_name = {service["name"]: service for service in data.get("services", [])}
    for name, overrides in local_by_name.items():
        if name in base_by_name:
            base_by_name[name].update(overrides)
        else:
            data.setdefault("services", []).append(overrides)
    return data


def _default_ingress(site: dict) -> str:
    if site.get("port") == 9090:
        return "direct"
    return "wiring-harness-caddy"


def _default_access_mode(site: dict) -> str:
    ingress = site.get("ingress")
    if ingress == "direct":
        return "vpn-only-direct"
    if site.get("client_ca_path"):
        return "snowbridge-mtls"
    return "shared-mtls"


def load_sites(services_path: Path = DEFAULT_SERVICES_TOML) -> list[dict]:
    """Return the merged site registry with defaults applied."""
    sites: list[dict] = []
    data = load_services_data(services_path)
    for raw_site in data.get("services", []):
        site = dict(raw_site)
        site.setdefault("description", "")
        site.setdefault("owner_repo", "")
        site.setdefault("ingress", _default_ingress(site))
        site.setdefault("access_mode", _default_access_mode(site))
        site.setdefault("dns_enabled", True)
        sites.append(site)
    return sites


def find_site(sites: list[dict], name: str) -> dict | None:
    """Find a site by registry name."""
    for site in sites:
        if site.get("name") == name:
            return site
    return None


def caddy_managed_sites(sites: list[dict]) -> list[dict]:
    """Return only sites whose host Caddy blocks are managed by wiring-harness."""
    return [site for site in sites if site.get("ingress") == "wiring-harness-caddy"]


def shared_server_cert_sites(sites: list[dict]) -> list[dict]:
    """Return sites whose hostname must appear in the shared server cert SANs."""
    return [
        site
        for site in sites
        if site.get("access_mode") in {"shared-mtls", "snowbridge-mtls"}
    ]


def dns_sites(sites: list[dict]) -> list[dict]:
    """Return sites that should resolve through the private VPN DNS layer."""
    return [site for site in sites if site.get("dns_enabled", True)]


def site_url(site: dict) -> str:
    """Return the user-facing URL for a site inventory entry."""
    hostname = site["hostname"]
    ingress = site.get("ingress")
    port = site.get("inventory_port", site.get("port"))
    if ingress == "direct" and port:
        port_num = int(port)
        if port_num not in (80, 443):
            return f"https://{hostname}:{port_num}"
    return f"https://{hostname}"


def render_inventory_markdown(sites: list[dict], services_path: Path = DEFAULT_SERVICES_TOML) -> str:
    """Render a concise Markdown inventory for private browser/admin sites."""
    lines = [
        "# Private Site Inventory",
        "",
        f"Generated from `{services_path.name}` plus local overrides.",
        "",
        "| Registry Name | URL | Owner | Access | Ingress | Description |",
        "|---|---|---|---|---|---|",
    ]
    ingress_labels = {
        "wiring-harness-caddy": "shared Caddy",
        "repo-caddy": "repo Caddy",
        "direct": "direct service",
    }
    for site in sites:
        description = site.get("description", "").replace("|", "/")
        owner = site.get("owner_repo", "").replace("|", "/")
        ingress = ingress_labels.get(site.get("ingress"), site.get("ingress", ""))
        lines.append(
            "| {name} | {url} | {owner} | {access} | {ingress} | {description} |".format(
                name=site["name"],
                url=site_url(site),
                owner=owner,
                access=site.get("access_mode", ""),
                ingress=ingress,
                description=description,
            )
        )
    lines.extend(
        [
            "",
            "Access modes:",
            "- `shared-mtls`: shared wiring-harness client cert/profile",
            "- `snowbridge-mtls`: Snowbridge-specific client cert/profile",
            "- `vpn-only-direct`: VPN-only service that is not fronted by the shared Caddy entrypoint",
        ]
    )
    return "\n".join(lines) + "\n"
