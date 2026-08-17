# Temporary macOS Private Edge

The Air edge is a render-only Caddy and launchd integration for accessing
reviewed loopback services over WireGuard. It does not activate Caddy, install
a LaunchAgent, create trust material, configure WireGuard, or expose a LAN/WAN
listener.

## Access Shape

The renderer creates IP-literal endpoints so first access from an iPhone does
not depend on a private DNS server:

| Role | iPhone endpoint | Reviewed backend | Required |
|---|---|---|---|
| Clockwork | `https://<air-wireguard-ip>:8443/` | `http://127.0.0.1:5001` | Yes |
| Snowbridge | `https://<air-wireguard-ip>:8444/` | `http://127.0.0.1:8080` | No |

Both endpoints require and verify a client certificate before proxying a
request. Caddy binds only the configured RFC1918 WireGuard `/32`; automatic
HTTP redirects and the Caddy admin API are disabled. No tracked Caddy drop-ins
are imported into this narrow Air configuration.

Caddy normally enforces equality between TLS SNI and the HTTP Host header when
client authentication is enabled. IP-literal clients such as `curl` and iOS do
not send an SNI hostname, so the rendered server sets `default_sni` to the same
validated WireGuard IP so the protected TLS policy is selected. Because the
original ClientHello still contains empty SNI, Caddy's SNI/Host equality check
would reject the subsequent IP Host with HTTP 421; the renderer therefore also
sets `strict_sni_host insecure_off`. This narrowly scoped exception is allowed
only because every site on the exact WireGuard `/32` bind uses the same
`require_and_verify` client-certificate policy. The Podman regression proves
that a client without a trusted identity is still rejected. Never reuse this
pair in a mixed-policy or public-facing server.

Ports 8443 and 8444 are deliberate. This bundle renders a user LaunchAgent,
which must not assume it can bind privileged port 443. A future port-443 design
needs a separately reviewed root LaunchDaemon or macOS packet-filter boundary;
changing either reviewed registry port is rejected.

## Private Registry Input

Keep the Air address and service selection in the existing canonical local
registry, not in a second edge-specific inventory:

```toml
[macos_private_edge]
wireguard_interface = "<utun-interface>"
wireguard_address = "<air-wireguard-ip>/32"

[[services]]
name                   = "clockwork-web"
description            = "Clockwork UI on Air"
owner_repo             = "./util-repos/clockwork"
hostname               = "clockwork.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 5001
macos_edge_role        = "clockwork"
macos_edge_listen_port = 8443

# Optional:
[[services]]
name                   = "snowbridge-filebrowser"
description            = "Snowbridge files on Air"
owner_repo             = "./util-repos/snowbridge"
hostname               = "files.air.internal"
access_mode            = "shared-mtls"
ingress                = "wiring-harness-caddy"
port                   = 8080
macos_edge_role        = "snowbridge"
macos_edge_listen_port = 8444
```

Replace the placeholder and save the content in gitignored
`services.local.toml`, then set `chmod 600 services.local.toml`. The renderer
rejects placeholder values, duplicate roles, nonstandard listener ports, unreviewed
owners/backends, Unix sockets, env-derived ports, proxy-header overrides,
non-mTLS access modes, public addresses, broad prefixes, and group/world
readable local state. It also reads the declared `utunN` interface and refuses
to render unless the exact WireGuard `/32` is currently assigned there; an
RFC1918 address by itself is not proof that the listener is mesh-only.

The reviewed Snowbridge role also overwrites `X-Snowbridge-Auth-User` with the
fixed local identity `snowbridge` before proxying to File Browser. Client input
can never select that identity; mTLS at this exact mesh listener is the trust
boundary. Clockwork does not receive this header.

## Certificate Input

The renderer requires these pre-existing owner-only files:

```text
~/.config/wiring-harness/certs/
├── server.crt   # server certificate with the Air WireGuard IP as an IP SAN
├── server.key   # matching server private key
└── ca.crt       # CA used to verify the iPhone client identity
```

Use `chmod 700 ~/.config/wiring-harness/certs` and `chmod 600` on all three
files. If Snowbridge uses a separate client CA, put its owner-only local path
in that service's `client_ca_path` field.

### Air-native bootstrap

Create a distinct Air CA, an IP-SAN server certificate, and a local validation
client with the macOS-safe bootstrap:

```bash
cd wiring-harness
python3 scripts/bootstrap_macos_air_pki.py
```

The default server IP SAN is `10.99.0.254`. Override it only when the reviewed
Air WireGuard address changes:

```bash
python3 scripts/bootstrap_macos_air_pki.py --wireguard-ip 10.99.0.253
```

The bootstrap invokes OpenSSL directly without a shell, creates the certificate
directory as mode `0700` and every file as mode `0600`, and validates the CA,
server and client key pairs, certificate chains, leaf EKUs, expiration, and
server IP SAN before installing the directory. It prints no private material
and does not read or modify Keychain, Caddy, launchd, or WireGuard state.

Its local layout is:

```text
~/.config/wiring-harness/certs/
├── air-ca.crt
├── air-ca.key     # remains only in this owner-only local directory
├── ca.crt         # client trust bundle consumed by the Air Caddy renderer
├── server.crt
├── server.key
├── client.crt     # local authenticated-edge validation identity
└── client.key
```

An existing valid directory is checked and left byte-for-byte unchanged.
Incomplete or incompatible state is refused. An intentional rotation requires
`--rotate`; the complete previous owner-only directory is first retained as a
timestamped sibling backup, and a failed install rolls back before returning.

To continue accepting client identities issued by the legacy Clockwork CA,
export only its public certificate first, then pass its path explicitly:

```bash
install -d -m 0700 "$HOME/.config/wiring-harness"
security find-certificate -c "Clockwork CA" -p \
  "$HOME/Library/Keychains/login.keychain-db" \
  > "$HOME/.config/wiring-harness/legacy-clockwork-client-ca.crt"
chmod 0600 "$HOME/.config/wiring-harness/legacy-clockwork-client-ca.crt"

python3 scripts/bootstrap_macos_air_pki.py \
  --legacy-client-ca "$HOME/.config/wiring-harness/legacy-clockwork-client-ca.crt"
```

That public certificate is appended to `ca.crt`; its private key is neither
needed nor requested. The Air CA remains first in the bundle and continues to
sign the Air server and local validation client. Passing a legacy file that
contains private-key material is rejected.

The existing `scripts/setup-mtls.sh` is a Linux host provisioner: it uses Bash
`readarray` and also renders Linux dnsmasq/system paths. Do not claim or assume
that it is an Air bootstrap. The Air-native helper above is the normal local
path. Alternatively, obtain externally issued Air inputs in one of these ways:

1. Restore the existing wiring-harness `server.crt`, `server.key`, and `ca.crt`
   from the private secret backup only if the server certificate already has
   the Air WireGuard IP SAN.
2. Have the existing private CA issuer create a server certificate
   for the Air WireGuard IP, then transfer only the three files above to Air
   over an authenticated private channel. The CA private key does not need to
   be copied to Air. Existing iPhone client identities must chain to `ca.crt`.

With Homebrew OpenSSL, inspect the received certificate without exposing its
key:

```bash
/opt/homebrew/bin/openssl x509 \
  -in "$HOME/.config/wiring-harness/certs/server.crt" \
  -noout -checkip <air-wireguard-ip>
```

The renderer independently decodes the certificate and refuses to render if
that IP SAN is absent.

## Render and Validate

Install Caddy separately, then render the local bundle:

```bash
brew install caddy
python3 scripts/render_macos_private_edge.py --validate-caddy
```

The gitignored output is
`config/macos-private-edge.local/` and contains an owner-only Caddyfile,
manifest, logs directory, and
`dev.user.wiring-harness.macos-private-edge.plist`. The manifest records the
literal URLs, certificate IP SAN requirement, reviewed upstreams, and whether
Caddy validation passed.

Rendering does not prove that WireGuard, Clockwork, or Snowbridge is running.
It also does not copy the plist to `~/Library/LaunchAgents` or call
`launchctl`; activation remains a separate operator-reviewed step after the
backend-specific repos provide their own macOS launch artifacts.

## Read-only live smoke checks

The rendered edge includes one owner-only JSON access log per role under
`config/macos-private-edge.local/logs/`. Caddy logs only a `GET` to the exact
role health path whose `wiring_harness_smoke` value is 16–128 URL-safe
characters. Ordinary browsing and malformed probe markers are skipped. For a
probe, Caddy copies only the opaque, non-secret correlation value and the
normalized fixed path into dedicated JSON fields, then deletes the complete
request URI along with request headers, TLS client metadata, and response
headers. Extra query parameters therefore cannot leak into the log. The log
directory is exactly mode `0700`; each current or rolled file is mode `0600`,
rolls at 1 MiB with a one-record allowance, and retains at most two rolled
files. Rendering creates an empty safe log when needed but never truncates an
existing one, and both rendering and readiness reject unsafe or excess rolls.

After an operator has reviewed, installed, and restarted the rendered
LaunchAgent, check local readiness without changing service state:

```bash
python3 scripts/check_macos_air_live.py readiness
```

The command verifies the exact `utunN` `/32`, installed-plist equality, the
active LaunchAgent's arguments, and that its process started after the exact
deterministically rendered Caddy policy. It also checks Caddy syntax and exact
TCP/UDP listeners, the server certificate IP SAN and expiry, owner-only bounded
log state, and direct Clockwork/Snowbridge loopback health. Client trust is
compared by effective X.509 authority identity (canonical subject plus public
key), not certificate bytes alone, so a reissued CA using the same authority
cannot be mislabeled isolated. The result is `single`, `shared`, `overlapping`,
or `distinct`; different bundles with any common authority are `overlapping`.

For an end-to-end check, pass only the phone's RFC1918 WireGuard `/32`; device
names, public keys, and peer authority remain in `short-circuit`:

```bash
python3 scripts/check_macos_air_live.py peer \
  --peer 10.99.0.241/32 \
  --timeout 90
```

Open both nonce-bearing URLs printed by the command on that phone. Readiness
first proves that the running process loaded the exact current
`require_and_verify` policy; a successful fresh access record then proves the
independent peer reached that mesh listener, completed accepted mTLS, traversed
Caddy, and received a successful response from the reviewed backend. Repeat
with each peer `/32` that needs coverage.

Do not replace this peer-driven check with host-side `curl` to the Air `/32`.
On macOS, the host route to its own point-to-point WireGuard address hairpins
into the `utun` interface and can time out even when the listener and remote
peers are healthy. The checker deliberately contacts only `127.0.0.1` from Air
and waits for an independent peer to exercise the HTTPS edge.

Rendering the new log policy remains inert. It does not update the installed
plist or make a running Caddy process reread its config. Any install or restart
is a separate operator action after reviewing the owner-only artifacts.
