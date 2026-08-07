#!/bin/sh

set -eu

hostname=nordility.test.internal
backend_pid=
caddy_pid=

cleanup() {
    test -z "$caddy_pid" || kill "$caddy_pid" >/dev/null 2>&1 || true
    test -z "$backend_pid" || kill "$backend_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

install -d -m 0700 /certs
install -d -m 0755 /etc/caddy/Caddyfile.d
: > /etc/caddy/Caddyfile.d/empty.caddy

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=wiring-harness test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout /certs/ca.key -out /certs/ca.crt >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -subj "/CN=$hostname" \
    -keyout /certs/server.key -out /tmp/server.csr >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$hostname" > /tmp/server.ext
openssl x509 -req -days 1 -in /tmp/server.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -extfile /tmp/server.ext -out /certs/server.crt >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -subj '/CN=container-test-client' \
    -keyout /certs/client.key -out /tmp/client.csr >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > /tmp/client.ext
openssl x509 -req -days 1 -in /tmp/client.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -extfile /tmp/client.ext -out /certs/client.crt >/dev/null 2>&1

cat > /tmp/services.toml <<EOF
wg_ip = "127.0.0.1"

[[services]]
name = "nordility"
description = "Unix socket integration test"
owner_repo = "./util-repos/nordility"
hostname = "$hostname"
access_mode = "shared-mtls"
ingress = "wiring-harness-caddy"
unix_socket = "/run/nordility/web.sock"
EOF

python3 /opt/wiring-harness/scripts/setup_caddy.py \
    --services /tmp/services.toml \
    --certs-dir /certs \
    --output /tmp/Caddyfile \
    --inventory-output /tmp/inventory.md \
    --validate >/tmp/render.out
grep -F 'reverse_proxy unix//run/nordility/web.sock' /tmp/Caddyfile >/dev/null

python3 /usr/local/bin/unix-http-backend &
backend_pid=$!
attempt=0
while [ ! -S /run/nordility/web.sock ] && [ "$attempt" -lt 100 ]; do
    attempt=$((attempt + 1))
    sleep 0.05
done
test -S /run/nordility/web.sock

caddy run --config /tmp/Caddyfile --adapter caddyfile >/tmp/caddy.out 2>&1 &
caddy_pid=$!

response=
attempt=0
while [ "$attempt" -lt 100 ]; do
    if response=$(curl --fail --silent --show-error --noproxy '*' \
        --cacert /certs/ca.crt \
        --cert /certs/client.crt \
        --key /certs/client.key \
        --resolve "$hostname:443:127.0.0.1" \
        "https://$hostname/health" 2>/dev/null); then
        break
    fi
    response=
    attempt=$((attempt + 1))
    sleep 0.05
done
test "$response" = 'nordility-unix-ok'

if curl --fail --silent --show-error --noproxy '*' \
    --cacert /certs/ca.crt \
    --resolve "$hostname:443:127.0.0.1" \
    "https://$hostname/health" >/dev/null 2>&1; then
    echo "Caddy accepted a client without an mTLS identity" >&2
    exit 1
fi

echo "Caddy mTLS to Unix-socket upstream passed"
