# wiring-harness

Shared Caddy, mTLS, and DNS provisioning for the home server portfolio.

Each private browser/admin site (clockwork-web, snowbridge-filebrowser,
pit-box-webterm, …) is declared once in `services.toml`. The provisioning
scripts read that registry to generate a combined Caddyfile for
`wiring-harness-caddy` entries, shared server TLS cert SANs for any shared-mTLS
hostnames, dnsmasq entries, and a local inventory report — so adding or moving
an endpoint is one registry edit, not a script edit in multiple repos.

Wireguard lives in `short-circuit`. SSH extensions live in `pit-box`.

## Scope

- mTLS CA and cert generation (shared server cert, per-device client certs)
- iOS/macOS mobileconfig export for WireGuard + mTLS access
- Combined Caddyfile generation from the service registry
- dnsmasq A-record config for internal hostnames
- System-level provisioning: cert install, Caddy restart, user linger
- Consent reference: [`../../doc-repos/my-consent/remote-access-and-private-files.md`](../../doc-repos/my-consent/remote-access-and-private-files.md) documents the explicit consent covering personal certificate, mobileconfig, device, and remote-access processing handled by this repo.

Out of scope: WireGuard setup (short-circuit), SSH (pit-box), service-specific
systemd unit management (each service repo handles its own).

## Quick Start

```bash
# 1. Edit services.toml / services.local.toml to register your private sites

# 2. Apply site registry changes end to end
scripts/apply_site_changes.sh
```

For first-time setup, or when you intentionally need to export fresh device
profiles, run the lower-level commands directly:

```bash
# Generate CA, server cert, client cert, and iOS mobileconfig
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh

# Install Caddyfile, copy certs, restart Caddy, enable linger
sudo python3 scripts/setup_caddy.py --provision

# Refresh the local inventory report (optional standalone step)
python3 scripts/render_private_site_inventory.py

# Issue a per-device Apple profile (repeat for each device)
sudo python3 scripts/export_mtls_profile.py --device-name iphone

# Restage an existing device profile without rotating its identity
sudo python3 scripts/restage_mtls_device.py --device-name iphone --show-passwords

# Inspect a device's actual artifact names and verify the PKCS#12 passwords
sudo python3 scripts/inspect_mtls_device.py --device-name iphone --show-passwords
```

## Adding a New Private Site

Add one `[[services]]` entry to `services.toml`:

```toml
[[services]]
name        = "my-new-app"
description = "My app UI"
owner_repo  = "./util-repos/my-app"
hostname    = "app.home.internal"
access_mode = "shared-mtls"
ingress     = "wiring-harness-caddy"
port        = 3000
```

If the hostname is used by a sibling repo's own Caddy drop-in or by a direct
VPN-only service, keep the same registry entry but set `ingress = "repo-caddy"`
or `ingress = "direct"` instead.

Then re-run provisioning:

```bash
scripts/apply_site_changes.sh
```

That refreshes the shared server cert SANs without rotating the CA, installs
the generated dnsmasq records, provisions Caddy, writes the local inventory,
and verifies each private hostname resolves to the WireGuard server IP.

## Service Registry (`services.toml`)

| Field | Description |
|---|---|
| `name` | Stable registry key used in filenames and cross-repo lookups |
| `description` | Human-readable label used in the generated inventory |
| `owner_repo` | Repo that owns the service or admin surface |
| `hostname` | Canonical private hostname |
| `access_mode` | `shared-mtls`, `snowbridge-mtls`, or `vpn-only-direct` |
| `ingress` | `wiring-harness-caddy`, `repo-caddy`, or `direct` |
| `port` | Backend port or direct service port (takes priority over env lookup) |
| `port_env_key` | Env var name to read port from `env_file` |
| `port_default` | Fallback port when env lookup finds nothing |
| `env_file` | Path to env file for port lookup |
| `url_scheme` | Optional inventory URL scheme for non-HTTPS direct services, for example `rdp` |
| `client_ca_path` | Override client CA; omit to use the shared wiring-harness CA |
| `proxy_headers` | Extra headers injected by Caddy into the upstream request |
| `dns_enabled` | Optional override; defaults to `true` for VPN DNS publication |

Only `ingress = "wiring-harness-caddy"` entries become blocks in the combined
host Caddyfile. `repo-caddy` and `direct` entries still appear in the local
inventory report and in the merged hostname lookup used by sibling repos.

## Local Inventory Report

The registry can also render a concise Markdown inventory of current private
sites, including owner repo, access mode, and ingress type.

```bash
python3 scripts/render_private_site_inventory.py
```

By default this writes `config/private-sites.inventory.local.md` (gitignored).

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

## Device Registry

`devices.toml` and gitignored `devices.local.toml` use `delivery` to describe
how the identity should be handed to the device:

- `delivery = "local-browser-install"`: install into local Firefox/Chromium NSS
  databases on the Linux machine running the script
- `delivery = "apple-profile"`: stage an Apple `mobileconfig` and PKCS#12
  bundle for import on iPhone, iPad, or macOS

Legacy `type = "desktop"` / `type = "mobile"` entries are still accepted as a
compatibility alias, but new or edited entries should use `delivery`.

When a device also needs Snowbridge's separate client CA, the export/restage
flow stages the Snowbridge PKCS#12 bundle alongside the main
`wiring-harness-mtls-<device>.p12` artifact.

System certs (readable by Caddy) are installed to `/etc/caddy/certs/wiring-harness/`.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/apply_site_changes.sh` | Fast one-command path after editing the private-site registry: refresh server cert SANs, install dnsmasq records, provision Caddy, and verify VPN DNS |
| `scripts/setup-mtls.sh` | Generate CA, server cert, client cert, mobileconfig, dnsmasq snippet |
| `scripts/setup_caddy.py --provision` | Install certs, generate Caddyfile, restart Caddy, enable linger |
| `scripts/render_private_site_inventory.py` | Render the merged private-site inventory as local Markdown |
| `scripts/export_mtls_profile.py` | Issue a per-device client cert and stage mobileconfig |
| `scripts/restage_mtls_device.py` | Rebuild and re-copy an existing device's staged profile artifacts without rotating the identity |
| `scripts/inspect_mtls_device.py` | Resolve a device's artifact paths and verify PKCS#12 import passwords |
| `scripts/deploy_snowbridge_filebrowser_fork_image.sh` | Build Snowbridge's patched File Browser image, update its env file, and recreate only the backend container |

## Snowbridge Backend Deploys

`wiring-harness` owns the shared Caddy entrypoint for
`https://files.snowbridge.internal`, so backend-only Snowbridge File Browser
deploys should happen from this repo instead of starting Snowbridge's optional
standalone Caddy stack on the same host.

```bash
./scripts/deploy_snowbridge_filebrowser_fork_image.sh
```

That helper reuses the sibling `snowbridge` repo's File Browser image builder,
writes `FILEBROWSER_IMAGE` into
`snowbridge/config/web/filebrowser/filebrowser.env.local`, and recreates only
the `filebrowser` service. If your repos are not siblings, pass
`--snowbridge-repo /path/to/snowbridge`.

If you changed `services.toml`, certs, hostnames, or the backend port, follow
the backend deploy with:

```bash
scripts/apply_site_changes.sh --skip-mtls
```
