#!/usr/bin/env bash
# Apply wiring-harness private-site registry changes end to end.
#
# This is the fast path after editing services.toml or services.local.toml:
# refresh the shared server certificate SANs, install the dnsmasq snippet,
# provision the combined Caddyfile, and verify VPN DNS answers.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/apply_site_changes.sh [options]

Options:
  --wg-ip IP              WireGuard server IP for DNS/SANs (default: WH_WG_IP or 10.99.0.1)
  --rotate                Rotate the wiring-harness CA and all leaf certificates
  --with-device-profiles  Re-export per-device mobile/browser profiles during the mTLS step
  --skip-mtls             Do not run setup-mtls.sh
  --skip-dnsmasq          Do not install/restart the dnsmasq snippet
  --skip-caddy            Do not run setup_caddy.py --provision
  --skip-dns-check        Do not verify hostnames through dnsmasq
  -h, --help              Show this help

Default behavior is optimized for adding or changing sites: refresh the server
cert, keep the existing CA/client certs, and skip per-device profile export.
Use --rotate only when you intentionally want to invalidate old profiles.
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${EUID}" -eq 0 ]]; then
  echo "error: run this as your normal user; the script uses sudo only for system writes." >&2
  exit 1
fi

wg_ip="${WH_WG_IP:-10.99.0.1}"
cert_dir="${WH_CERT_DIR:-$HOME/.config/wiring-harness/certs}"
mtls_mode="--refresh-server"
with_device_profiles=0
skip_mtls=0
skip_dnsmasq=0
skip_caddy=0
skip_dns_check=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wg-ip)
      if [[ $# -lt 2 ]]; then
        echo "error: --wg-ip requires a value" >&2
        exit 2
      fi
      wg_ip="$2"
      shift 2
      ;;
    --rotate)
      mtls_mode="--rotate"
      with_device_profiles=1
      shift
      ;;
    --with-device-profiles)
      with_device_profiles=1
      shift
      ;;
    --skip-mtls)
      skip_mtls=1
      shift
      ;;
    --skip-dnsmasq)
      skip_dnsmasq=1
      shift
      ;;
    --skip-caddy)
      skip_caddy=1
      shift
      ;;
    --skip-dns-check)
      skip_dns_check=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

run_step() {
  local title="$1"
  shift
  echo
  echo "==> $title"
  "$@"
}

require_cmd python3
require_cmd sudo

if [[ "$skip_mtls" -eq 0 ]]; then
  mtls_args=("$mtls_mode")
  if [[ "$with_device_profiles" -eq 0 && -f "$cert_dir/ca.crt" ]]; then
    mtls_args+=("--skip-device-profiles")
  fi
  run_step "Refreshing wiring-harness mTLS material" \
    env WH_WG_IP="$wg_ip" WH_CERT_DIR="$cert_dir" bash scripts/setup-mtls.sh "${mtls_args[@]}"
else
  echo "==> Skipping mTLS refresh"
fi

cert_parent="$(dirname "$cert_dir")"
if [[ -d "$cert_parent" ]]; then
  dns_snippet="$(cd "$cert_parent" && pwd)/dnsmasq-wiring-harness.conf"
else
  dns_snippet="$cert_parent/dnsmasq-wiring-harness.conf"
fi
if [[ "$skip_dnsmasq" -eq 0 ]]; then
  if [[ ! -f "$dns_snippet" ]]; then
    echo "error: dnsmasq snippet not found: $dns_snippet" >&2
    echo "  Run without --skip-mtls first, or set WH_CERT_DIR correctly." >&2
    exit 1
  fi
  run_step "Installing dnsmasq private-site records" \
    sudo install -D -m 0644 "$dns_snippet" /etc/dnsmasq.d/wiring-harness.conf
  if systemctl is-active --quiet dnsmasq; then
    run_step "Restarting dnsmasq" sudo systemctl restart dnsmasq
  else
    echo "warning: dnsmasq is not active; start it before testing phone DNS." >&2
  fi
else
  echo "==> Skipping dnsmasq install"
fi

if [[ "$skip_caddy" -eq 0 ]]; then
  run_step "Provisioning shared Caddy" \
    sudo python3 scripts/setup_caddy.py --provision --certs-dir "$cert_dir"
else
  echo "==> Skipping Caddy provision"
fi

if [[ "$skip_dns_check" -eq 0 ]]; then
  if command -v dig >/dev/null 2>&1; then
    mapfile -t dns_hostnames < <(
      PYTHONPATH="$repo_root/scripts${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PYEOF'
from site_registry import dns_sites, load_sites

for site in dns_sites(load_sites()):
    hostname = site.get("hostname", "").strip()
    if hostname:
        print(hostname)
PYEOF
    )
    echo
    echo "==> Verifying dnsmasq answers on $wg_ip"
    failed=0
    for hostname in "${dns_hostnames[@]}"; do
      answer="$(dig +short "@$wg_ip" "$hostname" A | tail -n 1 || true)"
      if [[ "$answer" == "$wg_ip" ]]; then
        printf '  ok   %-36s %s\n' "$hostname" "$answer"
      else
        printf '  fail %-36s got %s, expected %s\n' "$hostname" "${answer:-<none>}" "$wg_ip" >&2
        failed=1
      fi
    done
    if [[ "$failed" -ne 0 ]]; then
      echo "error: one or more DNS checks failed" >&2
      exit 1
    fi
  else
    echo "warning: dig is not installed; skipping DNS verification." >&2
  fi
else
  echo "==> Skipping DNS verification"
fi

echo
echo "Site integration complete."
echo "Reconnect WireGuard on phone clients so they pick up fresh DNS/cache state."
