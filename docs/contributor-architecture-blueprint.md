# Contributor Architecture Blueprint

## Runtime Flow

1. `services.toml` declares the shared HTTPS backends, their hostnames, and one
   loopback-TCP or permissioned Unix-socket upstream.
2. `scripts/setup-mtls.sh` generates or refreshes the shared CA, server
   certificate, client certificate, mobileconfig, and dnsmasq snippet.
3. `scripts/setup_caddy.py --provision` reads the service registry, renders the
   combined Caddy configuration, installs cert material, and restarts Caddy.
4. `scripts/export_mtls_profile.py` issues per-device client identities and
   stages mobileconfigs for device distribution.
5. Backend services remain owned by their individual repos; `wiring-harness`
   only manages the shared ingress and trust layer.
6. On the temporary macOS hub, `scripts/render_macos_private_edge.py` reads the
   same merged registry and renders a separate IP-literal Caddyfile plus an
   inert user LaunchAgent. It never imports the Linux-wide Caddyfile.

## Primary Components

- `services.toml` is the tracked source of truth for shared service ingress.
- `scripts/setup-mtls.sh` owns certificate and profile generation.
- `scripts/setup_caddy.py` owns Caddyfile rendering and system provisioning.
  It rejects mixed TCP/Unix declarations and renders Unix backends with
  Caddy's `unix//absolute/path.sock` address form.
- `scripts/render_macos_private_edge.py` owns the narrow Air render contract:
  an RFC1918 WireGuard `/32`, mandatory client-authenticated TLS, reviewed
  loopback ports, unprivileged listeners, and owner-only local artifacts.
- `scripts/export_mtls_profile.py` owns per-device client-profile issuance.
- `config/caddy/Caddyfile.example` and `config/dnsmasq/services.conf.example`
  show the expected generated shapes.

## Boundaries

- WireGuard tunnel creation stays in `short-circuit`.
- SSH extensions stay in `pit-box`.
- Service-local containers and systemd units stay in their own service repos.
- Service repos own Unix-socket creation, modes, and group assignment; the
  shared Caddy service must receive group traversal and connect permission.
- Generated keys, certificates, PKCS12 bundles, and local device state are
  operational artifacts and must not be committed.
- `setup-mtls.sh` remains Linux-oriented; the macOS renderer consumes an
  already-issued server certificate carrying the Air IP SAN and does not
  create or copy CA private keys.
