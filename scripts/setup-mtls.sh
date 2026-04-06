#!/usr/bin/env bash
# Generate CA, server, and client certificates for wiring-harness mTLS.
# Creates an iOS/macOS mobile profile and registers certs with desktop browsers.
#
# The server cert SANs are derived from services.toml (all service hostnames)
# plus the WireGuard IP.  Re-run any time the WireGuard IP or service list changes.
#
# Usage:
#   bash scripts/setup-mtls.sh                   # reads services.toml for SANs
#   WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${WH_CERT_DIR:-$HOME/.config/wiring-harness/certs}"
WG_IP="${WH_WG_IP:-10.99.0.1}"
DAYS_CA=3650
DAYS_LEAF=825  # ~2 years, max trusted by modern browsers

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# ── Derive SANs from services.toml ─────────────────────────────────────────────
# Extract all hostname values with a simple grep — avoids a toml parser dependency.
HOSTNAMES=$(grep -oP '(?<=hostname\s{0,5}=\s{0,5}")([^"]+)' "$REPO_ROOT/services.toml" 2>/dev/null || true)
if [ -z "$HOSTNAMES" ]; then
  echo "warning: no hostnames found in services.toml — using defaults" >&2
  HOSTNAMES="wiring-harness.internal"
fi

SAN_VALUE="subjectAltName=IP:${WG_IP}"
for hn in $HOSTNAMES; do
  SAN_VALUE="${SAN_VALUE},DNS:${hn}"
  echo "  SAN hostname: $hn"
done
echo "  SAN IP: $WG_IP"

PRIMARY_HOSTNAME=$(echo "$HOSTNAMES" | head -1)

# ── 1. CA ──────────────────────────────────────────────────────────────────────
echo "==> Generating CA (valid ${DAYS_CA} days)..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -new -x509 -days "$DAYS_CA" \
  -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=Wiring Harness CA/O=Portfolio/OU=Infrastructure"

# ── 2. Server cert ─────────────────────────────────────────────────────────────
echo "==> Generating server certificate (valid ${DAYS_LEAF} days)..."
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

# ── 3. Client cert ─────────────────────────────────────────────────────────────
echo "==> Generating client certificate (valid ${DAYS_LEAF} days)..."
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

# ── 4. PKCS12 bundle ───────────────────────────────────────────────────────────
echo "==> Bundling client cert as PKCS12..."
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

# ── 5. Mobile profile ──────────────────────────────────────────────────────────
echo "==> Generating mobile profile (.mobileconfig)..."
python3 - "$CERT_DIR" "$WG_IP" <<'PYEOF'
import hashlib, plistlib, ssl, sys, uuid
from pathlib import Path

cert_dir = Path(sys.argv[1])
wg_ip    = sys.argv[2]

def load_der(path):
    raw = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        return ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
    return raw

def stable_uuid(label, digest):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{label}:{digest}")).upper()

ca_der   = load_der(cert_dir / "ca.crt")
p12_data = (cert_dir / "client.p12").read_bytes()
digest   = hashlib.sha256(ca_der + p12_data).hexdigest()

profile = {
    "PayloadType": "Configuration",
    "PayloadVersion": 1,
    "PayloadIdentifier": "local.wiring-harness.mtls",
    "PayloadUUID": stable_uuid("wiring-harness-mtls-profile", digest),
    "PayloadDisplayName": f"Wiring Harness mTLS ({wg_ip})",
    "PayloadDescription": "Trust profile and client identity for private mTLS access over WireGuard.",
    "PayloadOrganization": "wiring-harness",
    "PayloadRemovalDisallowed": False,
    "PayloadContent": [
        {
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": "local.wiring-harness.mtls.root",
            "PayloadUUID": stable_uuid("wiring-harness-mtls-root", digest),
            "PayloadDisplayName": "Wiring Harness CA",
            "PayloadDescription": "Installs the Wiring Harness CA so the device trusts all private HTTPS endpoints.",
            "PayloadCertificateFileName": "ca.crt",
            "PayloadContent": ca_der,
        },
        {
            "PayloadType": "com.apple.security.pkcs12",
            "PayloadVersion": 1,
            "PayloadIdentifier": "local.wiring-harness.mtls.identity",
            "PayloadUUID": stable_uuid("wiring-harness-mtls-identity", digest),
            "PayloadDisplayName": "Wiring Harness mTLS Client Identity",
            "PayloadDescription": "Installs the client certificate for private mTLS access.",
            "PayloadCertificateFileName": "client.p12",
            "PayloadContent": p12_data,
        },
    ],
}

out = cert_dir / "wiring-harness.mobileconfig"
out.write_bytes(plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False))
out.chmod(0o644)
print(f"  Mobile profile: {out}")
PYEOF

# ── 6. Firefox NSS databases ───────────────────────────────────────────────────
echo "==> Adding certs to Firefox NSS databases..."
if command -v certutil >/dev/null 2>&1; then
  found_ff=0
  for profile_dir in \
      "$HOME"/.mozilla/firefox/*.default \
      "$HOME"/.mozilla/firefox/*.default-release \
      "$HOME"/.mozilla/firefox/*.default-esr \
      "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*.default-release; do
    [ -d "$profile_dir" ] || continue
    found_ff=1
    db="sql:$profile_dir"
    for nick in "Wiring Harness CA" "wiring-harness-client - Portfolio" "wiring-harness-client"; do
      for i in $(seq 1 10); do certutil -D -d "$db" -n "$nick" 2>/dev/null || break; done
    done
    if certutil -A -d "$db" -n "Wiring Harness CA" -t "CT,," -i "$CERT_DIR/ca.crt" 2>/dev/null; then
      echo "  [FF] CA added: $(basename "$profile_dir")"
    fi
    if pk12util -i "$CERT_DIR/client.p12" -d "$db" -W "$P12_PASS" 2>/dev/null; then
      echo "  [FF] Client cert added: $(basename "$profile_dir")"
    fi
  done
  [ "$found_ff" -eq 0 ] && echo "  No Firefox profiles found."
else
  echo "  certutil not found — install nss-tools"
fi

# ── 7. Chromium NSS ────────────────────────────────────────────────────────────
echo "==> Adding certs to Chromium NSS database..."
if command -v certutil >/dev/null 2>&1; then
  CHROMIUM_DB="$HOME/.pki/nssdb"
  if [ ! -d "$CHROMIUM_DB" ]; then
    mkdir -p "$CHROMIUM_DB"
    certutil -d "sql:$CHROMIUM_DB" -N --empty-password
  fi
  for nick in "Wiring Harness CA" "wiring-harness-client - Portfolio" "wiring-harness-client"; do
    for i in $(seq 1 10); do certutil -D -d "sql:$CHROMIUM_DB" -n "$nick" 2>/dev/null || break; done
  done
  certutil -A -d "sql:$CHROMIUM_DB" -n "Wiring Harness CA" -t "CT,," -i "$CERT_DIR/ca.crt" 2>/dev/null \
    && echo "  [Chromium] CA added." || echo "  [Chromium] CA add failed."
  pk12util -i "$CERT_DIR/client.p12" -d "sql:$CHROMIUM_DB" -W "$P12_PASS" 2>/dev/null \
    && echo "  [Chromium] Client cert added." || echo "  [Chromium] Client cert add failed."
fi

# ── 8. /etc/hosts entry ────────────────────────────────────────────────────────
for hn in $HOSTNAMES; do
  if getent hosts "$hn" >/dev/null 2>&1; then
    echo "  Already resolves: $(getent hosts "$hn")"
  else
    printf '127.0.0.1 %s\n' "$hn" | sudo tee -a /etc/hosts >/dev/null 2>&1 \
      && echo "  Added to /etc/hosts: 127.0.0.1 $hn" \
      || echo "  Could not write /etc/hosts — add manually: echo '127.0.0.1 $hn' | sudo tee -a /etc/hosts"
  fi
done

# ── 9. dnsmasq config ──────────────────────────────────────────────────────────
DNSMASQ_SNIPPET="$CERT_DIR/../dnsmasq-wiring-harness.conf"
DNSMASQ_DEST="/etc/dnsmasq.d/wiring-harness.conf"
{
  echo "# wiring-harness dnsmasq entries — generated by scripts/setup-mtls.sh"
  for hn in $HOSTNAMES; do
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
echo "  Client cert:    $CERT_DIR/client.crt"
echo "  Client p12:     $CERT_DIR/client.p12"
echo "  P12 passphrase: $P12_PASS  (saved to $P12_PASS_FILE)"
echo "  Mobile profile: $CERT_DIR/wiring-harness.mobileconfig"
echo ""
echo "Next step — install Caddy config:"
echo "  sudo python3 scripts/setup_caddy.py --provision"
echo ""
echo "Per-device mobileconfigs:"
echo "  sudo python3 scripts/export_mtls_profile.py --device-name iphone"
