#!/bin/sh

set -eu

wireguard_ip=10.99.0.254
clockwork_backend_pid=
snowbridge_backend_pid=
caddy_pid=

cleanup() {
    test -z "$caddy_pid" || kill "$caddy_pid" >/dev/null 2>&1 || true
    test -z "$clockwork_backend_pid" || kill "$clockwork_backend_pid" >/dev/null 2>&1 || true
    test -z "$snowbridge_backend_pid" || kill "$snowbridge_backend_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

report_failure() {
    echo "mTLS edge did not become ready" >&2
    test ! -s /tmp/curl.err || cat /tmp/curl.err >&2
    test ! -s /tmp/caddy.out || cat /tmp/caddy.out >&2
    exit 1
}

ip link add utun7 type dummy
ip address add "$wireguard_ip/32" dev utun7
ip link set utun7 up
install -d -m 0700 /certs

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=wiring-harness macOS edge test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout /certs/ca.key -out /certs/ca.crt >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -subj "/CN=$wireguard_ip" \
    -keyout /certs/server.key -out /tmp/server.csr >/dev/null 2>&1
printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$wireguard_ip" > /tmp/server.ext
openssl x509 -req -days 1 -in /tmp/server.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -extfile /tmp/server.ext -out /certs/server.crt >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -subj '/CN=iphone-container-test' \
    -keyout /certs/client.key -out /tmp/client.csr >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > /tmp/client.ext
openssl x509 -req -days 1 -in /tmp/client.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -extfile /tmp/client.ext -out /certs/client.crt >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=wiring-harness Snowbridge test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout /certs/snow-ca.key -out /certs/snow-ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=snowbridge-container-test' \
    -keyout /certs/snow-client.key -out /tmp/snow-client.csr >/dev/null 2>&1
openssl x509 -req -days 1 -in /tmp/snow-client.csr \
    -CA /certs/snow-ca.crt -CAkey /certs/snow-ca.key -CAcreateserial \
    -extfile /tmp/client.ext -out /certs/snow-client.crt >/dev/null 2>&1
openssl req -new -key /certs/snow-ca.key \
    -subj '/CN=wiring-harness Snowbridge test CA' \
    -out /tmp/snow-ca-reissued.csr >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > /tmp/ca.ext
openssl x509 -req -days 2 -set_serial 42 \
    -in /tmp/snow-ca-reissued.csr -signkey /certs/snow-ca.key \
    -extfile /tmp/ca.ext -out /certs/snow-ca-reissued.crt >/dev/null 2>&1
chmod 0600 /certs/*

openssl verify -CAfile /certs/snow-ca-reissued.crt /certs/snow-client.crt >/dev/null

cat > /tmp/reissued-services.toml <<'EOF'
# Public registry layer for the same-authority trust test.
EOF
cat > /tmp/reissued-services.local.toml <<'EOF'
[macos_private_edge]
wireguard_interface = "utun7"
wireguard_address = "10.99.0.254/32"

[[services]]
name                   = "clockwork-web"
owner_repo             = "./util-repos/clockwork"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 5001
client_ca_path         = "/certs/snow-ca.crt"
macos_edge_role        = "clockwork"
macos_edge_listen_port = 8443

[[services]]
name                   = "snowbridge-filebrowser"
owner_repo             = "./util-repos/snowbridge"
access_mode            = "snowbridge-mtls"
ingress                = "wiring-harness-caddy"
port                   = 8080
client_ca_path         = "/certs/snow-ca-reissued.crt"
macos_edge_role        = "snowbridge"
macos_edge_listen_port = 8444
EOF
chmod 0600 /tmp/reissued-services.local.toml
python3 /opt/wiring-harness/scripts/render_macos_private_edge.py \
    --services /tmp/reissued-services.toml \
    --certs-dir /certs \
    --output-dir /tmp/reissued-edge.local \
    --caddy-binary /usr/bin/caddy >/tmp/reissued-render.out
grep -F '"client_trust_topology": "shared"' /tmp/reissued-edge.local/manifest.json >/dev/null

cat > /tmp/services.toml <<'EOF'
# Public registry layer for the integration test.
EOF
cat > /tmp/services.local.toml <<EOF
[macos_private_edge]
wireguard_interface = "utun7"
wireguard_address = "$wireguard_ip/32"

[[services]]
name                   = "clockwork-web"
description            = "Container Clockwork backend"
owner_repo             = "./util-repos/clockwork"
hostname               = "clockwork.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 5001
macos_edge_role        = "clockwork"
macos_edge_listen_port = 8443

[[services]]
name                   = "snowbridge-filebrowser"
description            = "Container Snowbridge backend"
owner_repo             = "./util-repos/snowbridge"
hostname               = "files.air.internal"
access_mode            = "snowbridge-mtls"
ingress                = "wiring-harness-caddy"
port                   = 8080
client_ca_path         = "/certs/snow-ca.crt"
macos_edge_role        = "snowbridge"
macos_edge_listen_port = 8444
EOF
chmod 0600 /tmp/services.local.toml

python3 /opt/wiring-harness/scripts/render_macos_private_edge.py \
    --services /tmp/services.toml \
    --certs-dir /certs \
    --output-dir /tmp/macos-private-edge.local \
    --caddy-binary /usr/bin/caddy \
    --validate-caddy >/tmp/render.out

grep -F "https://$wireguard_ip:8443" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F "bind $wireguard_ip" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'reverse_proxy 127.0.0.1:5001' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'reverse_proxy 127.0.0.1:8080' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'header_up X-Snowbridge-Auth-User "snowbridge"' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F "@wiringHarnessSmoke \`method('GET') && path('/')" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F "@notWiringHarnessSmoke \`!(method('GET') && path('/')" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F "path('/health')" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F "matches('^[A-Za-z0-9_-]{16,128}$')" /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'log_append @wiringHarnessSmoke wiring_harness_smoke {query.wiring_harness_smoke}' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'log_append @wiringHarnessSmoke wiring_harness_path {path}' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'request>uri delete' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'request>headers delete' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'request>tls delete' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F 'resp_headers delete' /tmp/macos-private-edge.local/Caddyfile >/dev/null
grep -F '"validated": true' /tmp/macos-private-edge.local/manifest.json >/dev/null
grep -F '"wireguard_interface": "utun7"' /tmp/macos-private-edge.local/manifest.json >/dev/null
grep -F '"client_trust_topology": "distinct"' /tmp/macos-private-edge.local/manifest.json >/dev/null

python3 /usr/local/bin/macos-edge-http-backend 5001 clockwork-air-edge-ok &
clockwork_backend_pid=$!
python3 /usr/local/bin/macos-edge-http-backend 8080 snowbridge-air-edge-ok &
snowbridge_backend_pid=$!
caddy run --config /tmp/macos-private-edge.local/Caddyfile --adapter caddyfile >/tmp/caddy.out 2>&1 &
caddy_pid=$!

request() {
    request_path=${4:-/}
    curl --fail --silent --show-error --noproxy '*' \
        --connect-timeout 1 \
        --max-time 1 \
        --cacert /certs/ca.crt \
        --cert "$2" \
        --key "$3" \
        "https://$wireguard_ip:$1$request_path"
}

wait_for_service() {
    wait_port=$1
    wait_cert=$2
    wait_key=$3
    wait_expected=$4
    response=
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if response=$(request "$wait_port" "$wait_cert" "$wait_key" 2>/tmp/curl.err); then
            test "$response" = "$wait_expected" && return 0
        fi
        response=
        attempt=$((attempt + 1))
        sleep 0.05
    done
    report_failure
}

wait_for_service 8443 /certs/client.crt /certs/client.key clockwork-air-edge-ok
wait_for_service 8444 /certs/snow-client.crt /certs/snow-client.key snowbridge-air-edge-ok

proxy_identity=$(curl --fail --silent --show-error --noproxy '*' \
    --connect-timeout 1 --max-time 1 \
    --cacert /certs/ca.crt \
    --cert /certs/snow-client.crt \
    --key /certs/snow-client.key \
    --header 'X-Snowbridge-Auth-User: attacker-controlled' \
    "https://$wireguard_ip:8444/proxy-auth")
if [ "$proxy_identity" != snowbridge ]; then
    echo "Snowbridge proxy-auth header was not overwritten by the trusted edge" >&2
    exit 1
fi

for rejected_port in 8443 8444; do
    if curl --fail --silent --show-error --noproxy '*' \
        --connect-timeout 1 --max-time 1 \
        --cacert /certs/ca.crt \
        "https://$wireguard_ip:$rejected_port/" >/dev/null 2>&1; then
        echo "Air edge accepted a client without an mTLS identity on $rejected_port" >&2
        exit 1
    fi
done

if request 8443 /certs/snow-client.crt /certs/snow-client.key >/dev/null 2>&1; then
    echo "Clockwork accepted the Snowbridge client CA" >&2
    exit 1
fi
if request 8444 /certs/client.crt /certs/client.key >/dev/null 2>&1; then
    echo "Snowbridge accepted the Clockwork client CA" >&2
    exit 1
fi

explicit_sni_request() {
    printf 'GET / HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$wireguard_ip" "$1" | \
        openssl s_client -quiet \
            -connect "$wireguard_ip:$1" \
            -servername "$wireguard_ip" \
            -verify_return_error \
            -verify_ip "$wireguard_ip" \
            -CAfile /certs/ca.crt \
            -cert "$2" \
            -key "$3" 2>/tmp/openssl-client.err
}

explicit_clockwork=$(explicit_sni_request 8443 /certs/client.crt /certs/client.key)
printf '%s' "$explicit_clockwork" | grep -F clockwork-air-edge-ok >/dev/null
explicit_snowbridge=$(explicit_sni_request 8444 /certs/snow-client.crt /certs/snow-client.key)
printf '%s' "$explicit_snowbridge" | grep -F snowbridge-air-edge-ok >/dev/null
if explicit_sni_request 8444 /certs/client.crt /certs/client.key 2>/dev/null | \
    grep -F snowbridge-air-edge-ok >/dev/null; then
    echo "Snowbridge accepted the Clockwork CA with explicit SNI" >&2
    exit 1
fi
if explicit_sni_request 8443 /certs/snow-client.crt /certs/snow-client.key 2>/dev/null | \
    grep -F clockwork-air-edge-ok >/dev/null; then
    echo "Clockwork accepted the Snowbridge CA with explicit SNI" >&2
    exit 1
fi

clockwork_log=/tmp/macos-private-edge.local/logs/clockwork.access.json
snowbridge_log=/tmp/macos-private-edge.local/logs/snowbridge.access.json
test "$(stat -c '%a' "$clockwork_log")" = 600
test "$(stat -c '%a' "$snowbridge_log")" = 600
if test -s "$clockwork_log" || test -s "$snowbridge_log"; then
    echo "ordinary Air edge traffic leaked into probe-only access logs" >&2
    exit 1
fi

invalid_probe=$(request 8443 /certs/client.crt /certs/client.key "/?wiring_harness_smoke=short")
test "$invalid_probe" = clockwork-air-edge-ok
sleep 0.1
if test -s "$clockwork_log"; then
    echo "invalid live-smoke correlation value entered the access log" >&2
    exit 1
fi

probe_nonce=container-live-smoke-nonce
clockwork_probe=$(request 8443 /certs/client.crt /certs/client.key "/?wiring_harness_smoke=$probe_nonce")
test "$clockwork_probe" = clockwork-air-edge-ok
snowbridge_probe=$(request 8444 /certs/snow-client.crt /certs/snow-client.key "/health?wiring_harness_smoke=$probe_nonce")
test "$snowbridge_probe" = snowbridge-air-edge-ok

attempt=0
while { test ! -s "$clockwork_log" || test ! -s "$snowbridge_log"; } && test "$attempt" -lt 100; do
    attempt=$((attempt + 1))
    sleep 0.05
done
grep -F "\"wiring_harness_smoke\":\"$probe_nonce\"" "$clockwork_log" >/dev/null
grep -F "\"wiring_harness_smoke\":\"$probe_nonce\"" "$snowbridge_log" >/dev/null
grep -F '"wiring_harness_path":"/"' "$clockwork_log" >/dev/null
grep -F '"wiring_harness_path":"/health"' "$snowbridge_log" >/dev/null
test "$(grep -c '"uri"' "$clockwork_log")" -eq 0
test "$(grep -c '"uri"' "$snowbridge_log")" -eq 0
for sensitive_field in '"headers"' '"tls"' '"resp_headers"' '"client_common_name"' '"client_serial"'; do
    if grep -F "$sensitive_field" "$clockwork_log" "$snowbridge_log" >/dev/null; then
        echo "sensitive request metadata leaked into a live-smoke access log: $sensitive_field" >&2
        exit 1
    fi
done

echo "macOS Air two-role IP-literal mTLS isolation roundtrip passed"
