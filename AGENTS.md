# AGENTS.md — wiring-harness

## Purpose

`wiring-harness` owns the shared Caddy, mTLS, and DNS infrastructure for all
home-server services.  Services declare themselves in `services.toml`; the
provisioning scripts handle everything else.

WireGuard setup lives in `short-circuit`.  SSH extensions live in `pit-box`.
Service-specific systemd units and sudoers rules stay in each service's own repo.

## Repository Layout

- `services.toml`: service registry — one `[[services]]` entry per HTTPS site
- `scripts/setup-mtls.sh`: generates CA, server cert, client cert, mobileconfig, dnsmasq snippet
- `scripts/setup_caddy.py`: reads services.toml, generates Caddyfile, provisions system
- `scripts/export_mtls_profile.py`: issues per-device client certs and stages mobileconfigs
- `config/caddy/Caddyfile.example`: reference Caddyfile showing expected structure
- `config/dnsmasq/services.conf.example`: reference dnsmasq config

## Setup and Commands

```bash
# Full provisioning sequence
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh
sudo python3 scripts/setup_caddy.py --provision
sudo python3 scripts/export_mtls_profile.py --device-name iphone
```

## Operating Rules

1. `services.toml` is the single source of truth for which services exist.
   Adding a service means adding one TOML entry — never editing the scripts.
2. The server TLS cert covers all service hostnames as SANs.  Re-run
   `setup-mtls.sh` any time the hostname list or WireGuard IP changes, then
   re-run `setup_caddy.py --provision`.
3. Services with their own client CA (e.g. snowbridge) set `client_ca_path` in
   their services.toml entry.  All others share the wiring-harness CA.
4. `setup_caddy.py --provision` enables user lingering but does NOT manage
   individual service units.  Each service repo owns its own enable/disable.
5. Per-device mobileconfigs are staged to `/srv/snowbridge/share/tmp/` for
   easy distribution via the snowbridge SMB share.

## Agent Memory

Use `./LESSONSLEARNED.md` as the tracked durable lessons file for this repo.
Use `./CHATHISTORY.md` as the local-only handoff file (gitignored).

Read `LESSONSLEARNED.md` and `CHATHISTORY.md` after `AGENTS.md` when resuming work.

## Portfolio References

- `./util-repos/short-circuit` — WireGuard setup and peer config
- `./util-repos/pit-box` — SSH extensions
- `./util-repos/clockwork` — scheduler web app (clockwork-web)
- `./util-repos/snowbridge` — file sharing stack (filebrowser)
