# Contributor Architecture Blueprint

## Runtime Flow

1. `services.toml` declares the shared HTTPS backends and their hostnames.
2. `scripts/setup-mtls.sh` generates or refreshes the shared CA, server
   certificate, client certificate, mobileconfig, and dnsmasq snippet.
3. `scripts/setup_caddy.py --provision` reads the service registry, renders the
   combined Caddy configuration, installs cert material, and restarts Caddy.
4. `scripts/export_mtls_profile.py` issues per-device client identities and
   stages mobileconfigs for device distribution.
5. Backend services remain owned by their individual repos; `wiring-harness`
   only manages the shared ingress and trust layer.

## Primary Components

- `services.toml` is the tracked source of truth for shared service ingress.
- `scripts/setup-mtls.sh` owns certificate and profile generation.
- `scripts/setup_caddy.py` owns Caddyfile rendering and system provisioning.
- `scripts/export_mtls_profile.py` owns per-device client-profile issuance.
- `config/caddy/Caddyfile.example` and `config/dnsmasq/services.conf.example`
  show the expected generated shapes.

## Boundaries

- WireGuard tunnel creation stays in `short-circuit`.
- SSH extensions stay in `pit-box`.
- Service-local containers and systemd units stay in their own service repos.
- Generated keys, certificates, PKCS12 bundles, and local device state are
  operational artifacts and must not be committed.
