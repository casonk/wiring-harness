# PIN gate

A site in `services.toml` can ask for a 4-digit PIN before the shared Caddy serves it. The PIN is a
convenience lock on top of the shared mTLS requirement, not a replacement for it: 10,000 PINs are easy
to enumerate, so the gate is built around lockouts.

## Registry fields

```toml
[[services]]
name          = "magneto"
hostname      = "magneto.home.internal"
ingress       = "wiring-harness-caddy"   # required: only the shared Caddy can enforce a PIN
port          = 8081
pin           = true
pin_ttl_hours = 12                       # optional, default 12, at most 168
pin_entry     = "portfolio/pin/magneto"  # optional, default portfolio/pin/<name>
```

`pin = true` on any other ingress is an error. `repo-caddy` and `direct` sites have no gate, and a
registry that claimed one would be a lock that does not exist. Site names for PIN sites are lowercase
letters, digits, `-` and `_`.

## How it works

For a flagged site the generated Caddy block sends every request through `forward_auth` to
`pin_gate.py` on `127.0.0.1:8768` (`WH_PIN_GATE` overrides), and sends `/_pin/*` to the same service.
Caddy sets an `X-Pin-Site` header, so a client cannot ask about a different site than the one it reached.

- No valid cookie: a browser navigation is redirected (303) to the keypad; any other method gets 401.
- Correct PIN: a `__Host-pin` cookie (Secure, HttpOnly, SameSite=Strict, host-only) valid for the site's
  TTL. It is signed with a key derived from the shared signing key, the site name and that site's PIN, so a
  cookie opens only its own site and **changing a PIN signs everyone out of that site**.
- Secrets unavailable (auto-pass locked, entry missing): the gate answers 503. It never lets a request through.
- The keypad refuses cross-site POSTs, caps the body size, and never echoes a guess.

## Secrets

Nothing secret is in this repository. Each site has its own PIN, and one signing key is shared:

| Entry | Contents |
|---|---|
| `portfolio/pin/<site>` (or `pin_entry`) | the 4-digit PIN for that site |
| `portfolio/pin-signing-key` (`WH_PIN_SIGNING_KEY_ENTRY`) | a long random string; changing it signs everyone out of every site |

They are read through the auto-pass provisioning daemon (`auto-pass provision-get`), so the entries must be
approved for this repository and the daemon unlocked. Values are cached in memory for 10 minutes; restart
the service after changing one for it to take effect at once. Create the entries with `auto-pass set`
(see `auto-pass set --help`); do not paste a PIN into a shell argument.

## Lockouts

Two independent counters; a request is refused while **either** holds, even with the correct PIN.

| Counter | Keyed by | Default limit | Purpose |
|---|---|---|---|
| Site | site name | 5 wrong PINs, from anyone | stops a distributed guess at one PIN |
| IP | client address, across all sites | 10 wrong PINs | stops one client sweeping every site |

A lock lasts 15 minutes and doubles each time that counter locks again, up to 24 hours. A counter forgotten
after 24 hours without activity. A correct PIN clears only that site's counters, never the client's, so
knowing one PIN does not reset a guess in progress against another. Tune with `WH_PIN_SITE_MAX_FAILS`,
`WH_PIN_IP_MAX_FAILS`, `WH_PIN_BASE_LOCK_SECONDS`, `WH_PIN_MAX_LOCK_SECONDS`, `WH_PIN_DECAY_SECONDS`.

The per-site lock means anyone holding a valid client certificate can lock the owner out of a site. That is
deliberate: it is the control that bounds a stolen device. Lift a lock with `pin_gate.py reset`.

State is counts and timestamps only, in `~/.local/state/wiring-harness/pin-gate.json` (`WH_PIN_STATE`),
mode 0600, updated under a file lock, so a restart keeps a lock and `reset` works while the service runs.

## Notifications

A new lock is sent through shock-relay on every channel that has a target, never blocking the request:

```
WH_PIN_NOTIFY_SIGNAL_TARGET   WH_PIN_NOTIFY_SIGNAL_CONFIG
WH_PIN_NOTIFY_TELEGRAM_TARGET WH_PIN_NOTIFY_TELEGRAM_CONFIG
WH_PIN_NOTIFY_GMAIL_TARGET    WH_PIN_NOTIFY_GMAIL_CONFIG
WH_PIN_SHOCK_RELAY_ROOT       (default: the sibling shock-relay checkout)
```

Put them in the gitignored `~/.config/wiring-harness/pin-gate.env`. With no target the gate logs a warning
at start and still enforces. The message names the site or address and the lock length, never a PIN.

## Operating it

```bash
python3 scripts/pin_gate.py serve                  # or the user unit in config/systemd/
python3 scripts/pin_gate.py status                 # active locks and failure counts
python3 scripts/pin_gate.py reset --site magneto   # also --ip ADDRESS or --all
sudo python3 scripts/setup_caddy.py --provision    # after adding or removing pin = true
```

Logs go to stderr (the journal under `SyslogIdentifier=wiring-harness-pin-gate`); `--log-level` or
`WIRING_HARNESS_LOG_LEVEL` sets the level. Wrong PINs, locks and unlocks are logged with the site and
address, never the guess.

## Limits

A PIN gates the HTTP surface only; it does not protect a backend reachable another way. A 4-digit PIN
without lockouts is not a secret, so do not run the gate with the limits raised to the point they do not bite.
