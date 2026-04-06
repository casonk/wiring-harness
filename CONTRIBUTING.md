# Contributing

`wiring-harness` owns the shared Caddy, mTLS, and DNS infrastructure for the portfolio.

## Workflow

1. When adding a new service, register it in `services.toml` first.
2. When adding a new device, register it in `devices.toml` then run `sudo python3 scripts/export_mtls_profile.py --all-devices`.
3. After any cert or Caddy config change, run `sudo python3 scripts/setup_caddy.py --provision` to apply.
4. Re-run `bash scripts/setup-mtls.sh` any time the WireGuard IP or service list changes.

## Content Standards

- Keep `services.toml` and `devices.toml` as the single source of truth for provisioning.
- Do not commit generated certs, keys, or p12 bundles — those live in `~/.config/wiring-harness/certs/`.
- Use Conventional Commits such as `feat: add service` or `fix: correct SAN hostname`.
- Provisioning scripts must remain idempotent where possible.

## Pull Requests

- Keep each pull request focused on one provisioning concern.
- Note whether certs need to be regenerated and re-installed after the change.
- Confirm no secrets or local-only files are included.
