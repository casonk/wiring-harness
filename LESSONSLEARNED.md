# LESSONSLEARNED.md

Tracked durable lessons for `wiring-harness`.

## How To Use

- Read after `AGENTS.md` and before `CHATHISTORY.md` when resuming work.
- Add lessons that generalize beyond a single session.
- Keep entries concise and action-oriented.

## Lessons

- Caddy caches TLS cert files in memory on startup. `systemctl reload` or
  `reload-or-restart` sends SIGHUP but does NOT re-read cert files from disk.
  Always use `systemctl restart caddy` after rotating or replacing certs.
- `systemctl` read-only queries (is-active, is-enabled, show) work for system
  units without sudo. Only writes (enable, disable, daemon-reload) need elevation.
- iOS Safari strictly enforces TLS SANs. The server cert must include every
  service hostname as a DNS SAN and the WireGuard IP as an IP SAN or the
  connection will fail with "cannot verify server identity".
- When the device CA changes (e.g. setup-mtls.sh is re-run), the old client
  cert becomes invalid because it was signed by the old CA. Re-issue client
  certs and re-push the mobileconfig to all devices.
- Firefox and Chromium NSS databases accumulate duplicate cert entries on
  repeated `certutil -A` / `pk12util -i` calls. Pre-delete matching nicknames
  with a `certutil -D` loop before importing to avoid "duplicate certificate"
  failures.
- When migrating a service from repo-local TLS to shared-Caddy TLS, purge the
  legacy service CA/client nicknames from Firefox and Chromium NSS databases or
  browsers can keep offering the stale client identity and trusting the wrong
  chain even after the shared CA is installed.
- When wiring-harness owns shared Caddy on ports 80/443, service-specific deploy
  helpers must only restart backend services. Starting a second Caddy stack
  from the service repo will collide on host ports and bypass shared mTLS
  policy.
- Keep a single canonical hostname per service in `services.toml` unless a
  second hostname is intentionally required; typo-compat aliases expand the
  TLS SAN surface area and can linger longer than intended.
