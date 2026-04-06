# wiring-harness

Shared Caddy, mTLS, and DNS provisioning for the home server portfolio.

Each service (clockwork-web, snowbridge-filebrowser, …) is declared once in
`services.toml`. The provisioning scripts read that registry to generate a
combined Caddyfile, shared server TLS cert, per-service client CA config, and
dnsmasq entries — so adding a new service is one config entry, not a script edit.

Wireguard lives in `short-circuit`. SSH extensions live in `pit-box`.

## Scope

- mTLS CA and cert generation (shared server cert, per-device client certs)
- iOS/macOS mobileconfig export for WireGuard + mTLS access
- Combined Caddyfile generation from the service registry
- dnsmasq A-record config for internal hostnames
- System-level provisioning: cert install, Caddy restart, user linger

Out of scope: WireGuard setup (short-circuit), SSH (pit-box), service-specific
systemd unit management (each service repo handles its own).

## Quick Start

```bash
# 1. Edit services.toml to register your services

# 2. Generate CA, server cert, client cert, and iOS mobileconfig
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh

# 3. Install Caddyfile, copy certs, restart Caddy, enable linger
sudo python3 scripts/setup_caddy.py --provision

# 4. Issue a per-device mobileconfig (repeat for each device)
sudo python3 scripts/export_mtls_profile.py --device-name iphone
```

## Adding a New Service

Add one `[[services]]` entry to `services.toml`:

```toml
[[services]]
name     = "my-new-app"
hostname = "app.home.internal"
port     = 3000
```

Then re-run provisioning:

```bash
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh   # regenerates server cert SANs
sudo python3 scripts/setup_caddy.py --provision
```

## Service Registry (`services.toml`)

| Field | Description |
|---|---|
| `name` | Identifier used in filenames and log output |
| `hostname` | DNS hostname served by Caddy |
| `port` | Backend port (takes priority over env lookup) |
| `port_env_key` | Env var name to read port from `env_file` |
| `port_default` | Fallback port when env lookup finds nothing |
| `env_file` | Path to env file for port lookup |
| `client_ca_path` | Override client CA; omit to use the shared wiring-harness CA |
| `proxy_headers` | Extra headers injected by Caddy into the upstream request |

## Cert Layout

```
~/.config/wiring-harness/certs/
├── ca.crt / ca.key           shared CA
├── server.crt / server.key   server TLS cert (all service hostnames as SANs)
├── client.crt / client.p12   desktop browser client identity
├── client.p12.passphrase
├── wiring-harness.mobileconfig
└── issued/                   per-device client identities
    └── wiring-harness-mtls-<device>.*
```

System certs (readable by Caddy) are installed to `/etc/caddy/certs/wiring-harness/`.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/setup-mtls.sh` | Generate CA, server cert, client cert, mobileconfig, dnsmasq snippet |
| `scripts/setup_caddy.py --provision` | Install certs, generate Caddyfile, restart Caddy, enable linger |
| `scripts/export_mtls_profile.py` | Issue a per-device client cert and stage mobileconfig |
