# Changelog

All notable changes to `wiring-harness` are documented here.

## Unreleased

### Security

- Added an owner-only Air Apple-profile exporter for Mini and Pro with distinct
  client-only identities, password-free mobileconfigs, full source validation,
  explicit backed-up rotation, stable replacement UUIDs, and a validated
  clipboard-only passphrase helper that never writes the password to stdout.
  PKCS#12 private keys are matched to their leaves, the live multi-root Caddy
  trust bundle must contain the Air root exactly once, and explicit rotation
  can safely renew only selected expired or near-expiry leaves.
- Tolerate Finder's exact `.DS_Store` sidecar only at the owner-only Air profile
  root and delivery directory, while continuing to reject it from identity/PKI
  state and rejecting unsafe or unknown sidecars everywhere.
- The Air Snowbridge mTLS role now overwrites the File Browser proxy-auth
  identity header, with unit and two-role Podman regression coverage for
  attacker-supplied header replacement.
- Added an Air-native PKI bootstrap that creates owner-only CA, server, and
  local-client material through shell-free OpenSSL calls; validates key pairs,
  chains, EKUs, expiry, and the exact WireGuard IP SAN; refuses implicit
  overwrite; and retains a complete owner-only backup on explicit rotation.
- The Air client trust bundle can append an explicitly supplied legacy public
  Clockwork CA without requiring, copying, or printing its private key.
- Air live-smoke access logs are owner-only, size/count bounded, restricted to
  exact bounded probe markers on fixed health paths, and stripped of full URIs,
  request headers, TLS-client metadata, and response headers; renderer and
  readiness checks reject unsafe directories, current logs, and roll sets.
- Air trust-topology reporting now compares canonical CA subjects plus public
  keys, conservatively treating same-key reissued roots as shared authority.
- Removed explicit filesystem paths (`env_file`, `client_ca_path`) and personal
  device names from committed config files. Both are now kept in gitignored
  `services.local.toml` / `devices.local.toml`; committed example templates
  (`services.example.toml`, `devices.example.toml`) document the format.
- `setup_caddy.py` and `export_mtls_profile.py` now auto-merge the
  `*.local.toml` sibling file at load time, matching entries by `name`.

### Features

- Added a render-only macOS private edge that consumes the canonical local
  registry, binds IP-literal mTLS sites to one WireGuard `/32`, proxies only
  reviewed Clockwork/Snowbridge loopback ports, and emits an inert user
  LaunchAgent plus a machine-readable manifest.
- Covered Caddy's IP-literal client-auth behavior with an exact-IP
  `default_sni` plus a narrowly scoped SNI/Host equality exception, guarded by
  real Podman authenticated-round-trip and unauthenticated-client rejection
  regressions.
- The macOS edge now verifies that its exact `/32` belongs to the declared
  `utunN` interface and writes outputs with owner/ancestor validation plus
  same-directory atomic replacement.
- Added a read-only macOS Air checker for exact listener, certificate,
  LaunchAgent, backend, and trust-topology readiness plus nonce-correlated
  end-to-end checks driven by an independent RFC1918 WireGuard peer `/32`.
- Added `scripts/deploy_snowbridge_filebrowser_fork_image.sh` to manage
  Snowbridge File Browser fork deployments from `wiring-harness`, keeping host
  Caddy ownership in this repo.
- Added `--refresh-server` flag to `setup-mtls.sh` for refreshing the server
  cert SANs without regenerating the CA.
- `setup_caddy.py --provision` now manages the `# wiring-harness` block in
  `/etc/hosts` to keep `.internal` entries in sync with `services.toml`.
- Registered `tachometer` dashboard at `tachometer.internal:5100`.
- Registered `intake` reports at `receipts.intake.internal:5200`.
- Idempotent provisioning: `setup_caddy.py` skips cert copy if unchanged;
  desktop cert installs automatically restart affected browsers.

### Fixes

- Replaced fragile grep-based SAN extraction in `setup-mtls.sh` with Python
  `tomllib` parsing; initialised Chrome NSS db if absent before first browser
  launch.
- Fixed `pkill` browser matching to use `-f` (full command line) instead of
  `-x` so names longer than 15 characters (e.g. `chromium-browser`) match.
- Fixed `setup-mtls.sh` to use `tomllib.load()` (binary mode) instead of
  `loads(bytes)`.
- `export_mtls_profile.py` now purges legacy `Clockwork CA` and
  `clockwork-client` NSS nicknames on every desktop cert install.

### Initial release

- Initialized `wiring-harness` as the shared Caddy, mTLS, and DNS
  infrastructure repo for the portfolio.
- Migrated mTLS cert generation, Caddy provisioning, and DNS setup out of
  `clockwork` and `snowbridge` into this repo.
- Added `services.toml` as the service registry driving Caddyfile generation,
  server cert SANs, and per-service client CA configuration.
- Added `devices.toml` as the device registry for per-device cert issuance and
  delivery.
- Implemented `scripts/setup-mtls.sh`, `scripts/export_mtls_profile.py`, and
  `scripts/setup_caddy.py`.
- Added traction-control standard baseline: LICENSE, CONTRIBUTING,
  CODE_OF_CONDUCT, SECURITY, CI workflow, pre-commit config, GitHub
  issue/PR templates.
