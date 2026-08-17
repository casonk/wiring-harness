# AGENTS.md — wiring-harness

## Purpose

For portfolio-wide repository standards and baseline conventions, consult the control-plane repo at `./util-repos/traction-control` from the portfolio root.

`wiring-harness` owns the shared Caddy, mTLS, and DNS infrastructure for all
home-server services. Services declare themselves in `services.toml`; that
registry is also the canonical inventory for private browser/admin endpoints,
including repo-managed Caddy drop-ins and direct VPN-only surfaces.

WireGuard setup lives in `short-circuit`.  SSH extensions live in `pit-box`.
Service-specific systemd units and sudoers rules stay in each service's own repo.

## Repository Layout

- `services.toml`: private site registry — one `[[services]]` entry per private browser/admin endpoint
- `scripts/setup-mtls.sh`: generates CA, server cert, client cert, mobileconfig, dnsmasq snippet
- `scripts/setup_caddy.py`: reads services.toml, generates Caddyfile, provisions system
- `scripts/bootstrap_macos_air_pki.py`: creates and validates owner-only Air PKI material
- `scripts/export_macos_air_profiles.py`: creates owner-only Mini/Pro Apple profiles from the Air CA
- `scripts/render_macos_private_edge.py`: renders an inert, IP-literal macOS Caddy/launchd bundle
- `scripts/check_macos_air_live.py`: performs read-only Air readiness and independent-peer live-smoke checks
- `scripts/render_private_site_inventory.py`: renders a local Markdown inventory from the merged registry
- `scripts/export_mtls_profile.py`: issues per-device client certs and stages mobileconfigs
- `config/caddy/Caddyfile.example`: reference Caddyfile showing expected structure
- `config/dnsmasq/services.conf.example`: reference dnsmasq config

## Setup and Commands

```bash
# Full provisioning sequence
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh
sudo python3 scripts/setup_caddy.py --provision
sudo python3 scripts/export_mtls_profile.py --device-name iphone

# Render the owner-only Air edge without activating Caddy or launchd
python3 scripts/bootstrap_macos_air_pki.py
python3 scripts/export_macos_air_profiles.py
python3 scripts/render_macos_private_edge.py --validate-caddy
```

## Operating Rules

1. `services.toml` is the single source of truth for private site hostnames and
   ownership. Adding or moving a site means updating one TOML entry — never
   hard-coding a second hostname list in sibling repos.
2. The server TLS cert covers all service hostnames as SANs.  Re-run
   `setup-mtls.sh` any time the hostname list or WireGuard IP changes, then
   re-run `setup_caddy.py --provision`.
3. Services with their own client CA (e.g. snowbridge) set `client_ca_path` in
   their services.toml entry.  All others share the wiring-harness CA.
4. `setup_caddy.py --provision` enables user lingering but does NOT manage
   individual service units.  Each service repo owns its own enable/disable.
5. Per-device mobileconfigs are staged to `/srv/snowbridge/share/tmp/` for
   easy distribution via the snowbridge SMB share.
6. The macOS private-edge renderer is intentionally render-only. It consumes
   owner-only local registry/certificate inputs and must never invoke
   `launchctl`, install a plist, create a CA, or fall back to a wildcard bind.
7. The macOS Air PKI bootstrap owns only its local certificate directory. It
   must use direct OpenSSL argument vectors, never print private material, and
   never import into Keychain or activate a service.
8. Air device-profile generation preserves complete identities by default,
   requires explicit rotation, keeps identity state separate from delivery
   profiles, and must never print or embed a PKCS#12 passphrase.

## Sudo Boundary

Agents will never be able to run `sudo` commands in this environment. If a task requires elevated system changes, make the repo edits and run the validation that can be done without `sudo`, then give the user the exact command(s) to run.

Always require the user to run those commands instead of retrying `sudo`; do not claim a sudo-backed live change was applied until the user shares the result.

## Local CI Verification

Run before every push:

```bash
pre-commit run --all-files
```

Do not push changes that have not passed all checks locally.

## Agent Memory

Use `./LESSONSLEARNED.md` as the tracked durable lessons file for this repo.
Use `./CHATHISTORY.md` as the local-only handoff file (gitignored).

Read `LESSONSLEARNED.md` and `CHATHISTORY.md` after `AGENTS.md` when resuming work.

## Portfolio References

- `./util-repos/short-circuit` — WireGuard setup and peer config
- `./util-repos/pit-box` — SSH extensions
- `./util-repos/clockwork` — scheduler web app (clockwork-web)
- `./util-repos/snowbridge` — file sharing stack (filebrowser)
- `./util-repos/shock-relay` — messaging relay (Signal, Telegram, WhatsApp, Twilio SMS, Gmail IMAP); use `services/gmail-imap/send_email.py <to> <subject> <body>` to send email when Gmail MCP tools are unavailable
