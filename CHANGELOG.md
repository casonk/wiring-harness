# Changelog

All notable changes to `wiring-harness` are documented here.

## Unreleased

- Initialized `wiring-harness` as the shared Caddy, mTLS, and DNS infrastructure repo for the portfolio.
- Migrated mTLS cert generation, Caddy provisioning, and DNS setup out of `clockwork` and `snowbridge` into this repo.
- Added `services.toml` as the service registry driving Caddyfile generation, server cert SANs, and per-service client CA configuration.
- Added `devices.toml` as the device registry for per-device cert issuance and delivery.
- Implemented `scripts/setup-mtls.sh` for CA, server cert, shared client cert, PKCS12 bundle, /etc/hosts entries, and dnsmasq config generation.
- Implemented `scripts/export_mtls_profile.py` for per-device cert dispatch: NSS install for desktop Linux, mobileconfig staging for iOS devices.
- Implemented `scripts/setup_caddy.py` for Caddyfile generation and Caddy service management.
- Added traction-control standard baseline: LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CI workflow, pre-commit config, GitHub issue/PR templates.
