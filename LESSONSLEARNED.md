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
