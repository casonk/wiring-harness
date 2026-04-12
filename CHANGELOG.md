# Changelog

All notable changes to `wiring-harness` are documented here.

## Unreleased

### Security

- Removed explicit filesystem paths (`env_file`, `client_ca_path`) and personal
  device names from committed config files. Both are now kept in gitignored
  `services.local.toml` / `devices.local.toml`; committed example templates
  (`services.example.toml`, `devices.example.toml`) document the format.
- `setup_caddy.py` and `export_mtls_profile.py` now auto-merge the
  `*.local.toml` sibling file at load time, matching entries by `name`.

### Features

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
