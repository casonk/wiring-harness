#!/usr/bin/env python3
"""Install the combined Caddyfile for all services registered in services.toml.

Each [[services]] entry in services.toml becomes one mTLS-protected HTTPS site.
All sites share one server TLS cert (with SANs covering every hostname).
Client auth uses per-service CAs: omit client_ca_path to use the shared
wiring-harness CA; set it explicitly for services with their own CA.

Typical usage:
    sudo python3 scripts/setup_caddy.py --provision

This will:
  1. Copy TLS certs to /etc/caddy/certs/wiring-harness/
  2. Write /etc/caddy/Caddyfile
  3. caddy validate
  4. systemctl restart caddy
  5. loginctl enable-linger <invoking user>

Options:
    --provision          Full install: copy certs, write Caddyfile, restart Caddy,
                         enable lingering (needs root)
    --services PATH      Path to services.toml (default: ../services.toml)
    --certs-dir DIR      User cert directory (default: ~/.config/wiring-harness/certs)
    --output PATH        Also write a reference Caddyfile copy
                         (default: config/caddy/Caddyfile.combined.local)
    --validate           Run caddy validate without installing
"""

from __future__ import annotations

import argparse
import contextlib
import os
import pwd
import shutil
import subprocess
import sys
import tomllib  # type: ignore[no-redef]
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

DEFAULT_SERVICES_TOML = REPO_ROOT / "services.toml"
DEFAULT_USER_CERTS_DIR = Path.home() / ".config" / "wiring-harness" / "certs"
DEFAULT_SYSTEM_CERTS_DIR = Path("/etc/caddy/certs/wiring-harness")
DEFAULT_OUTPUT = REPO_ROOT / "config" / "caddy" / "Caddyfile.combined.local"
SYSTEM_CADDYFILE = Path("/etc/caddy/Caddyfile")
HOSTS_FILE = Path("/etc/hosts")
HOSTS_MARKER_BEGIN = "# wiring-harness BEGIN"
HOSTS_MARKER_END = "# wiring-harness END"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def _invoking_user() -> str | None:
    return os.environ.get("SUDO_USER")


def _invoking_user_home() -> Path:
    sudo_user = _invoking_user()
    if sudo_user:
        with contextlib.suppress(KeyError):
            return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _invoking_uid() -> int | None:
    sudo_user = _invoking_user()
    if sudo_user:
        with contextlib.suppress(KeyError):
            return pwd.getpwnam(sudo_user).pw_uid
    return None


def _caddy_gid() -> int | None:
    try:
        import grp
        return grp.getgrnam("caddy").gr_gid
    except (KeyError, ImportError):
        return None


def _update_hosts(hostnames: list[str]) -> None:
    """Maintain a wiring-harness managed block in /etc/hosts."""
    text = HOSTS_FILE.read_text()
    lines = text.splitlines(keepends=True)

    # Strip any existing managed block
    out: list[str] = []
    inside = False
    for line in lines:
        stripped = line.rstrip("\n")
        if stripped == HOSTS_MARKER_BEGIN:
            inside = True
            continue
        if stripped == HOSTS_MARKER_END:
            inside = False
            continue
        if not inside:
            out.append(line)

    # Ensure file ends with a newline before appending
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"

    # Append new managed block
    block: list[str] = [HOSTS_MARKER_BEGIN + "\n"]
    for h in hostnames:
        block.append(f"127.0.0.1 {h}\n")
    block.append(HOSTS_MARKER_END + "\n")

    HOSTS_FILE.write_text("".join(out + block))


def _parse_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        text = path.read_text()
    except PermissionError:
        rc, out = _run(["sudo", "cat", str(path)])
        text = out if rc == 0 else ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().split("#")[0].strip().strip('"').strip("'")
        if key.strip():
            env[key.strip()] = value
    return env


def _resolve_port(svc: dict, home: Path) -> int:
    if "port" in svc:
        return int(svc["port"])
    env_file_raw = svc.get("env_file")
    port_env_key = svc.get("port_env_key")
    port_default = int(svc.get("port_default", 8080))
    if env_file_raw and port_env_key:
        env_path = Path(env_file_raw.replace("~", str(home))).expanduser()
        if not env_path.is_absolute():
            env_path = (home / env_file_raw).resolve()
        if env_path.exists():
            env = _parse_env_file(env_path)
            with contextlib.suppress(ValueError, KeyError):
                return int(env[port_env_key])
    return port_default


def _resolve_client_ca(svc: dict, system_certs_dir: Path) -> Path:
    if "client_ca_path" in svc:
        return Path(svc["client_ca_path"])
    return system_certs_dir / "ca.crt"


# ---------------------------------------------------------------------------
# Caddyfile generation
# ---------------------------------------------------------------------------


def _site_block(
    hostname: str,
    cert: str,
    key: str,
    client_ca: str,
    proxy_target: str,
    proxy_headers: dict[str, str],
) -> str:
    header_lines = "\n".join(
        f"\t\theader_up {k} {v}" for k, v in proxy_headers.items()
    )
    proxy_extra = f" {{\n{header_lines}\n\t}}" if header_lines else ""
    return (
        f"https://{hostname} {{\n"
        f"\ttls {cert} {key} {{\n"
        f"\t\tclient_auth {{\n"
        f"\t\t\tmode require_and_verify\n"
        f"\t\t\ttrust_pool file {client_ca}\n"
        f"\t\t}}\n"
        f"\t}}\n"
        f"\n"
        f"\tencode zstd gzip\n"
        f"\treverse_proxy {proxy_target}{proxy_extra}\n"
        f"\n"
        f"\theader {{\n"
        f'\t\tX-Content-Type-Options "nosniff"\n'
        f'\t\tX-Frame-Options "SAMEORIGIN"\n'
        f'\t\tReferrer-Policy "no-referrer"\n'
        f"\t}}\n"
        f"}}"
    )


def generate_caddyfile(services: list[dict], system_certs_dir: Path, home: Path) -> str:
    cert = str(system_certs_dir / "server.crt")
    key = str(system_certs_dir / "server.key")

    blocks: list[str] = []
    for svc in services:
        hostname = svc["hostname"]
        port = _resolve_port(svc, home)
        client_ca = str(_resolve_client_ca(svc, system_certs_dir))
        proxy_headers = dict(svc.get("proxy_headers") or {})
        blocks.append(
            f"# {svc['name']} — {hostname}\n"
            + _site_block(hostname, cert, key, client_ca, f"127.0.0.1:{port}", proxy_headers)
        )

    return (
        "{\n"
        "\temail admin@example.com\n"
        "}\n\n"
        "# Combined Caddyfile — generated by wiring-harness/scripts/setup_caddy.py\n\n"
        + "\n\n".join(blocks)
        + "\n"
    )


# ---------------------------------------------------------------------------
# Provision
# ---------------------------------------------------------------------------


def provision(*, services_data: dict, user_certs_dir: Path) -> int:
    if os.geteuid() != 0:
        print("error: --provision must be run with sudo", file=sys.stderr)
        return 1

    services = services_data.get("services", [])
    home = _invoking_user_home()
    caddy_gid = _caddy_gid()

    # ── 1. Create system certs directory ──────────────────────────────────────
    DEFAULT_SYSTEM_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DEFAULT_SYSTEM_CERTS_DIR, 0o750)
    if caddy_gid:
        os.chown(DEFAULT_SYSTEM_CERTS_DIR, 0, caddy_gid)

    # ── 2. Copy shared server cert and CA ──────────────────────────────────────
    for name, mode in [("server.crt", 0o644), ("server.key", 0o640), ("ca.crt", 0o644)]:
        src = user_certs_dir / name
        if not src.exists():
            print(f"error: cert not found: {src}", file=sys.stderr)
            print("  Run: bash scripts/setup-mtls.sh", file=sys.stderr)
            return 1
        dst = DEFAULT_SYSTEM_CERTS_DIR / name
        shutil.copy2(src, dst)
        os.chmod(dst, mode)
        if caddy_gid:
            os.chown(dst, 0, caddy_gid)
        print(f"  copied {name} → {dst}")

    # ── 3. Copy per-service client CAs ────────────────────────────────────────
    for svc in services:
        ca_path_raw = svc.get("client_ca_path")
        if not ca_path_raw:
            continue  # uses shared CA, already copied above
        ca_src = Path(ca_path_raw)
        if not ca_src.exists():
            print(f"warning: client CA not found for {svc['name']}: {ca_src}", file=sys.stderr)
            print(f"  {svc['name']} mTLS client auth will not work until the CA is present.", file=sys.stderr)
            continue
        dst_name = f"{svc['name']}-client-ca.crt"
        dst = DEFAULT_SYSTEM_CERTS_DIR / dst_name
        shutil.copy2(ca_src, dst)
        os.chmod(dst, 0o644)
        if caddy_gid:
            os.chown(dst, 0, caddy_gid)
        # Update the svc dict so generate_caddyfile sees the system path
        svc["client_ca_path"] = str(dst)
        print(f"  copied {svc['name']} client CA → {dst}")

    # ── 4. SELinux contexts ───────────────────────────────────────────────────
    rc_se, out_se = _run(["restorecon", "-Rv", str(DEFAULT_SYSTEM_CERTS_DIR)])
    if rc_se == 0:
        for cert_file in DEFAULT_SYSTEM_CERTS_DIR.iterdir():
            _run(["chcon", "-t", "httpd_config_t", str(cert_file)])
        print("  restorecon: ok")
    elif rc_se != 127:
        print(f"warning: restorecon failed: {out_se}", file=sys.stderr)

    # ── 5. Update /etc/hosts managed block ───────────────────────────────────
    hostnames = [svc["hostname"] for svc in services]
    _update_hosts(hostnames)
    print(f"  updated {HOSTS_FILE} ({len(hostnames)} entries)")

    # ── 6. Generate and write /etc/caddy/Caddyfile ────────────────────────────
    content = generate_caddyfile(services, DEFAULT_SYSTEM_CERTS_DIR, home)
    SYSTEM_CADDYFILE.write_text(content)
    print(f"  wrote {SYSTEM_CADDYFILE}")

    DEFAULT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT.write_text(content)
    print(f"  wrote reference copy: {DEFAULT_OUTPUT}")

    # ── 7. Validate ───────────────────────────────────────────────────────────
    rc, out = _run(["caddy", "validate", "--config", str(SYSTEM_CADDYFILE)])
    if rc != 0:
        print(f"error: caddy validate failed:\n{out}", file=sys.stderr)
        return 1
    print("  caddy validate: ok")

    # ── 8. Restart Caddy ──────────────────────────────────────────────────────
    rc, out = _run(["systemctl", "restart", "caddy"], timeout=120)
    if rc != 0:
        print(f"error: systemctl restart caddy failed:\n{out}", file=sys.stderr)
        return 1
    print("  systemctl restart caddy: ok")

    # ── 9. Enable user lingering ──────────────────────────────────────────────
    sudo_user = _invoking_user()
    if sudo_user:
        rc_l, out_l = _run(["loginctl", "enable-linger", sudo_user])
        if rc_l == 0:
            print(f"  loginctl enable-linger {sudo_user}: ok")
        else:
            print(f"warning: loginctl enable-linger failed: {out_l}", file=sys.stderr)
    else:
        print("info: SUDO_USER not set — skipping linger (run: loginctl enable-linger $USER)")

    print()
    for svc in services:
        port = _resolve_port(svc, home)
        print(f"  https://{svc['hostname']}  → 127.0.0.1:{port}")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Install the combined Caddyfile from wiring-harness/services.toml.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--provision", action="store_true",
                   help="Copy certs, write Caddyfile, restart Caddy, enable linger (needs root)")
    p.add_argument("--services", metavar="PATH", default=str(DEFAULT_SERVICES_TOML),
                   help=f"Path to services.toml (default: {DEFAULT_SERVICES_TOML})")
    home = _invoking_user_home()
    default_certs = home / ".config" / "wiring-harness" / "certs"
    p.add_argument("--certs-dir", metavar="DIR", default=str(default_certs),
                   help="User cert directory (default: ~/.config/wiring-harness/certs)")
    p.add_argument("--output", metavar="PATH", default=str(DEFAULT_OUTPUT),
                   help=f"Reference Caddyfile output (default: {DEFAULT_OUTPUT})")
    p.add_argument("--validate", action="store_true",
                   help="Run caddy validate without installing")
    args = p.parse_args(argv)

    services_path = Path(args.services)
    if not services_path.exists():
        print(f"error: services.toml not found: {services_path}", file=sys.stderr)
        return 1

    services_data = tomllib.loads(services_path.read_text())
    certs_dir = Path(args.certs_dir).expanduser()

    if args.provision:
        return provision(services_data=services_data, user_certs_dir=certs_dir)

    # Reference Caddyfile only (no install)
    certs_ref = DEFAULT_SYSTEM_CERTS_DIR if DEFAULT_SYSTEM_CERTS_DIR.exists() else certs_dir
    content = generate_caddyfile(services_data.get("services", []), certs_ref, home)

    output_path = Path(args.output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    print(f"wrote: {output_path}")

    if args.validate:
        rc, out = _run(["caddy", "validate", "--config", str(output_path)])
        if rc != 0:
            print(f"caddy validate failed:\n{out}", file=sys.stderr)
            return 1
        print("caddy validate: ok")

    print()
    print("To install system-wide (needs root):")
    print("  sudo python3 scripts/setup_caddy.py --provision")
    return 0


if __name__ == "__main__":
    sys.exit(main())
