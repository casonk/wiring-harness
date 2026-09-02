# LESSONSLEARNED.md

Tracked durable lessons for `wiring-harness`.

## How To Use

- Read after `AGENTS.md` and before `CHATHISTORY.md` when resuming work.
- Add lessons that generalize beyond a single session.
- Keep entries concise and action-oriented.

## Lessons

- Portfolio-general WireGuard/VPN and TLS/Caddy lessons live in
  `traction-control/LESSONSLEARNED.md` (agents read it first); the entries here
  are repo-specific. The Caddy "reload does not re-read certs; restart after
  rotation" rule was up-integrated there.
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
- If sibling repos need private hostnames for browser/admin surfaces, put those
  hostnames in the merged `services.toml` / `services.local.toml` registry and
  have the sibling repo consume the registry instead of maintaining a second
  hostname list in its own config file.
- When a private host works from host-side `curl --resolve ... --cert ...` but
  fails from an iPhone over WireGuard, compare the generated
  `~/.config/wiring-harness/dnsmasq-wiring-harness.conf` with the live
  `/etc/dnsmasq.d/` files. A correct local registry plus an uninstalled dnsmasq
  snippet leaves Caddy and certs healthy while mobile clients still cannot
  resolve the hostname.
- When Gmail MCP tools are unavailable or disconnected, send email via
  shock-relay: `python3 "$SHOCK_RELAY_ROOT/services/gmail-imap/send_email.py" <to> <subject> <body>`
  where `SHOCK_RELAY_ROOT` is the local path to the sibling shock-relay repo.
- Per-device certificate exports should ship a local inspection helper that
  resolves the real staged filenames and validates each PKCS#12 passphrase
  against the actual artifact; filename drift and multi-identity Apple profiles
  are too error-prone for ad hoc shell commands.
- If a low-level export tool already supports a safe restage path, expose that
  path as a first-class repo helper instead of making users remember internal
  flags and behavior.
- When a schema field actually describes delivery mechanics rather than device
  class, name it for the behavior (`delivery`) instead of overloading a
  misleading label like `type`.
- Privileged control backends should expose a group-permissioned Unix socket to
  shared Caddy. Treat TCP ports and Unix sockets as mutually exclusive registry
  upstream types, and validate the complete target before rendering Caddy.
- A macOS user LaunchAgent must not be rendered with an assumed privileged
  port-443 bind. Use an explicit unprivileged listener or model a separate,
  reviewed root LaunchDaemon boundary.
- IP-literal private HTTPS removes the immediate iPhone DNS dependency, but the
  server certificate must contain that WireGuard address as an IP SAN. Bind
  Caddy explicitly to the RFC1918 `/32`; a site address alone is not the
  listener boundary.
- An RFC1918 `/32` is not inherently a WireGuard address. A mesh-only renderer
  must verify that the exact address is currently assigned to the declared
  `utunN` interface before producing activation artifacts.
- Caddy enables strict SNI/Host matching automatically when TLS client auth is
  configured, while IP-literal clients do not send an SNI hostname. Setting
  `default_sni` to the validated WireGuard IP selects the intended mTLS policy,
  but the original empty SNI still fails the automatic SNI/Host equality check.
  `strict_sni_host insecure_off` is acceptable only on an exact private bind
  where every site has one uniform mTLS policy, with a real unauthenticated
  client rejection test guarding against a fallback unprotected policy.
- The Linux-oriented `setup-mtls.sh` is not an honest macOS bootstrap because
  it uses Bash/Linux provisioning assumptions. macOS renderers should consume
  pre-issued owner-only cert material and clearly preserve CA-key custody.
- Keep temporary-edge PKI distinct and locally rotatable. Build it in an
  owner-only sibling staging directory, validate every key pair, chain, EKU,
  expiry, and IP SAN before installing it, and preserve the complete previous
  directory before an explicit rotation. A legacy client trust anchor needs
  only its public certificate, never its CA private key.
- Apple mobileconfig files are obfuscated transport, not encrypted secret
  storage. Embed only the encrypted PKCS#12 identity, keep its password in
  separate owner-only state, and deliver the password directly to a validated
  clipboard command rather than stdout. Keep profile UUIDs stable by device
  and payload role so rotation replaces instead of accumulating identities.
- Treat a PKCS#12 MAC and embedded leaf as insufficient proof of a usable
  identity: extract its private key without a shell, derive its public key,
  and compare that digest to the leaf. Before issuance, also require the live
  ingress trust bundle to contain the exact issuing root exactly once.
- Rotation recovery may waive certificate-time checks only for a selected
  expired or near-expiry leaf. Its ownership, manifests, key pairing, chain,
  EKU, and PKCS#12 integrity remain mandatory, and every preserved identity
  stays under strict time validation.
- macOS Finder can create a mode-0644 `.DS_Store` merely by opening a private
  delivery folder. Tolerate that exact, inert sidecar only on GUI-facing paths
  beneath a validated mode-0700 root; validate it with `lstat`, never package
  it, and keep identity and PKI directories strict.
- Rotating an mTLS leaf does not revoke its predecessor when the ingress trusts
  only the issuing CA and has no leaf revocation mechanism. Treat suspected
  leaf compromise as a CA-rotation event and reissue every device.
- Do not use an Air host request to its own point-to-point WireGuard `/32` as a
  live ingress check. macOS routes that destination into the `utun` interface,
  so the request can time out while remote peers and the listener are healthy.
  Probe loopback backends locally, then correlate a narrowly logged successful
  mTLS request from an independent mesh peer for end-to-end evidence.
- Different CA certificate fingerprints do not prove different trust
  authorities. Reissued roots can retain the same subject and public key and
  validate the same leaves; compare effective subject-plus-SPKI identities
  before claiming role isolation.
- With Caddy's admin API disabled, a valid file on disk does not prove the live
  process loaded it. Bind readiness to deterministic config equality, active
  launchd arguments, and a process start time newer than the rendered policy
  before using an access record as mTLS evidence.
- A macOS private edge may need separate loopback and mesh entrypoints for one
  service. Keep the browser's direct-on-host Home route on loopback and expose
  the same service to peers only through the exact WireGuard listener with
  mandatory mTLS; never replace either boundary with a wildcard listener.
