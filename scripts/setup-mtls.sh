#!/usr/bin/env bash
# Generate CA, server cert, and shared client cert for wiring-harness mTLS.
# Server cert SANs are derived from the merged private site registry
# (services.toml + services.local.toml) for any hostname that uses the shared
# wiring-harness server cert, plus the WireGuard IP.
#
# Per-device profiles (mobileconfigs for iPhones, NSS installs for desktop) are
# issued by export_mtls_profile.py --all-devices, which runs automatically at
# the end of this script.  Re-run any time the WireGuard IP or service list changes.
#
# Usage:
#   bash scripts/setup-mtls.sh                   # install/re-provision; skip cert gen if certs exist
#   bash scripts/setup-mtls.sh --refresh-server  # regenerate server cert only (new SANs, same CA/clients)
#   bash scripts/setup-mtls.sh --rotate          # force-regenerate all certs (new CA, server, clients)
#   WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh
set -euo pipefail

ROTATE=0
REFRESH_SERVER=0
for arg in "$@"; do
  case "$arg" in
    --rotate)         ROTATE=1 ;;
    --refresh-server) REFRESH_SERVER=1 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${WH_CERT_DIR:-$HOME/.config/wiring-harness/certs}"
WG_IP="${WH_WG_IP:-10.99.0.1}"
DAYS_CA=3650
DAYS_LEAF=825  # ~2 years, max trusted by modern browsers

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# ── Derive SANs and DNS hostnames from the merged site registry ──────────────
readarray -t SAN_HOSTNAMES < <(
  PYTHONPATH="$REPO_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PYEOF'
from site_registry import load_sites, shared_server_cert_sites

for site in shared_server_cert_sites(load_sites()):
    hostname = site.get("hostname", "").strip()
    if hostname:
        print(hostname)
PYEOF
)

readarray -t DNS_HOSTNAMES < <(
  PYTHONPATH="$REPO_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PYEOF'
from site_registry import dns_sites, load_sites

for site in dns_sites(load_sites()):
    hostname = site.get("hostname", "").strip()
    if hostname:
        print(hostname)
PYEOF
)

if [ "${#SAN_HOSTNAMES[@]}" -eq 0 ]; then
  echo "warning: no shared-mTLS hostnames found in the merged site registry — using defaults" >&2
  SAN_HOSTNAMES=("wiring-harness.internal")
fi

if [ "${#DNS_HOSTNAMES[@]}" -eq 0 ]; then
  DNS_HOSTNAMES=("${SAN_HOSTNAMES[@]}")
fi

SAN_VALUE="subjectAltName=IP:${WG_IP}"
for hn in "${SAN_HOSTNAMES[@]}"; do
  SAN_VALUE="${SAN_VALUE},DNS:${hn}"
  echo "  SAN hostname: $hn"
done
echo "  SAN IP: $WG_IP"

PRIMARY_HOSTNAME="${SAN_HOSTNAMES[0]}"

# ── Shared: generate server cert signed by existing CA ────────────────────────
_gen_server_cert() {
  openssl genrsa -out "$CERT_DIR/server.key" 2048
  openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=${PRIMARY_HOSTNAME}/O=Wiring Harness/OU=Server"
  openssl x509 -req -days "$DAYS_LEAF" \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -extfile <(printf "%s" "$SAN_VALUE") \
    -out "$CERT_DIR/server.crt"
  rm -f "$CERT_DIR/server.csr"
  echo "  server.crt SANs: $SAN_VALUE"
}

# ── 1–4. Cert generation ───────────────────────────────────────────────────────
if [ "$ROTATE" -eq 1 ] || [ ! -f "$CERT_DIR/ca.crt" ]; then
  if [ "$ROTATE" -eq 1 ]; then
    echo "==> --rotate: regenerating all certificates..."
  else
    echo "==> No existing certs found — generating fresh PKI..."
  fi

  # 1. CA
  openssl genrsa -out "$CERT_DIR/ca.key" 4096
  openssl req -new -x509 -days "$DAYS_CA" \
    -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/CN=Wiring Harness CA/O=Portfolio/OU=Infrastructure"

  # 2. Server cert
  _gen_server_cert

  # 3. Shared client cert (desktop fallback — per-device certs issued by export_mtls_profile.py)
  openssl genrsa -out "$CERT_DIR/client.key" 2048
  openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/CN=wiring-harness-client/O=Portfolio/OU=Admin"
  openssl x509 -req -days "$DAYS_LEAF" \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n") \
    -out "$CERT_DIR/client.crt"
  rm -f "$CERT_DIR/client.csr"

  # 4. PKCS12 bundle (shared cert)
  P12_PASS_FILE="$CERT_DIR/client.p12.passphrase"
  if [ ! -f "$P12_PASS_FILE" ]; then
    openssl rand -base64 24 > "$P12_PASS_FILE"
    chmod 600 "$P12_PASS_FILE"
  fi
  P12_PASS="$(cat "$P12_PASS_FILE")"
  openssl pkcs12 -export \
    -out "$CERT_DIR/client.p12" \
    -inkey "$CERT_DIR/client.key" \
    -in "$CERT_DIR/client.crt" \
    -certfile "$CERT_DIR/ca.crt" \
    -passout pass:"$P12_PASS"

  chmod 600 "$CERT_DIR"/*.key "$CERT_DIR"/*.p12
  echo "==> Certificates written to $CERT_DIR"

elif [ "$REFRESH_SERVER" -eq 1 ]; then
  echo "==> --refresh-server: regenerating server cert with current SANs (CA and client certs unchanged)..."
  _gen_server_cert
  chmod 600 "$CERT_DIR/server.key"
  echo "==> Server cert refreshed"

else
  echo "==> Existing certs found — skipping generation (use --rotate to regenerate)"
  echo "    CA: $CERT_DIR/ca.crt ($(openssl x509 -noout -enddate -in "$CERT_DIR/ca.crt" 2>/dev/null | cut -d= -f2))"
fi

# ── 5. /etc/hosts entries ──────────────────────────────────────────────────────
echo "==> Checking /etc/hosts..."
for hn in "${DNS_HOSTNAMES[@]}"; do
  if getent hosts "$hn" >/dev/null 2>&1; then
    echo "  Already resolves: $(getent hosts "$hn")"
  else
    printf '127.0.0.1 %s\n' "$hn" | sudo tee -a /etc/hosts >/dev/null 2>&1 \
      && echo "  Added to /etc/hosts: 127.0.0.1 $hn" \
      || echo "  Could not write /etc/hosts — add manually: echo '127.0.0.1 $hn' | sudo tee -a /etc/hosts"
  fi
done

# ── 6. dnsmasq config ──────────────────────────────────────────────────────────
DNSMASQ_SNIPPET="$CERT_DIR/../dnsmasq-wiring-harness.conf"
DNSMASQ_DEST="/etc/dnsmasq.d/wiring-harness.conf"
{
  echo "# wiring-harness dnsmasq entries — generated by scripts/setup-mtls.sh"
  for hn in "${DNS_HOSTNAMES[@]}"; do
    echo "address=/${hn}/${WG_IP}"
  done
} > "$DNSMASQ_SNIPPET"
echo "  dnsmasq snippet: $DNSMASQ_SNIPPET"

if [ -d /etc/dnsmasq.d ]; then
  if [ -w /etc/dnsmasq.d ]; then
    cp "$DNSMASQ_SNIPPET" "$DNSMASQ_DEST"
    echo "  Installed: $DNSMASQ_DEST"
    systemctl is-active --quiet dnsmasq 2>/dev/null && systemctl restart dnsmasq && echo "  Restarted dnsmasq."
  else
    echo "  Not writable — install manually: sudo cp $DNSMASQ_SNIPPET $DNSMASQ_DEST && sudo systemctl restart dnsmasq"
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "Certificates written to: $CERT_DIR"
echo "  CA cert:        $CERT_DIR/ca.crt"
echo "  Server cert:    $CERT_DIR/server.crt"
echo "  Shared client:  $CERT_DIR/client.crt / client.p12"
echo ""
echo "Next step — install Caddy config:"
echo "  sudo python3 scripts/setup_caddy.py --provision"

# ── 7. Per-device profiles for all registered devices ─────────────────────────
EXPORT_SCRIPT="$REPO_ROOT/scripts/export_mtls_profile.py"
DEVICES_TOML="$REPO_ROOT/devices.toml"
if [ -f "$EXPORT_SCRIPT" ] && [ -f "$DEVICES_TOML" ]; then
  echo ""
  echo "==> Issuing per-device profiles (devices.toml)..."
  if sudo python3 "$EXPORT_SCRIPT" --all-devices \
      --ca-cert "$CERT_DIR/ca.crt" \
      --ca-key "$CERT_DIR/ca.key" \
      --issued-dir "$CERT_DIR/issued"; then
    echo ""
    echo "Per-device profiles complete."
    echo "  Desktop certs installed to browser NSS databases."
    echo "  Mobile mobileconfigs staged to $DNSMASQ_SNIPPET"
    echo "  Mobile mobileconfigs staged to $(dirname "$DNSMASQ_SNIPPET")/snowbridge/share/tmp/"
  else
    echo "  Per-device export failed — run manually:"
    echo "    sudo python3 $EXPORT_SCRIPT --all-devices"
  fi
else
  echo ""
  echo "  devices.toml or export script not found — run manually:"
  echo "    sudo python3 scripts/export_mtls_profile.py --all-devices"
fi
