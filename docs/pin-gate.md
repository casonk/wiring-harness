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
`pin_gate.py` on `127.0.0.1:8781` (`WH_PIN_GATE` overrides), and sends `/_pin/*` to the same service.
Caddy sets an `X-Pin-Site` header, so a client cannot ask about a different site than the one it reached.

- No valid cookie: a browser navigation is redirected (303) to the keypad; any other method gets 401.
- Correct PIN: a `__Host-pin` cookie (Secure, HttpOnly, SameSite=Strict, host-only) valid for the site's
  TTL. It is signed with a key derived from the shared signing key, the site name and that site's PIN, so a
  cookie opens only its own site and **changing a PIN signs everyone out of that site**.
- Secrets unavailable (auto-pass locked, entry missing): the gate answers 503. It never lets a request through.
- The keypad refuses cross-site POSTs, caps the body size, and never echoes a guess.

## Secrets

The entries live in the `infra` vault, not `master`: they are service credentials, and `master` is the broadest
vault (it also holds the passwords that unlock the others), so the gate is never granted access to it.

Nothing secret is in this repository. Each site has its own PIN, and one signing key is shared:

| Entry | Contents |
|---|---|
| `portfolio/pin/<site>` (or `pin_entry`) | the 4-digit PIN for that site |
| `portfolio/pin-signing-key` (`WH_PIN_SIGNING_KEY_ENTRY`) | a long random string; changing it signs everyone out of every site |

They are read from the `infra` vault (`WH_PIN_VAULT` overrides) through the auto-pass provisioning daemon
(`auto-pass provision-get --db infra`), so the daemon must be unlocked and auto-pass's local allowlist needs a
`[repos.wiring-harness.vaults.infra]` block whose `allowed_paths` are `portfolio/pin/*` and
`portfolio/pin-signing-key`. Values are cached in memory for 10 minutes; restart
the service after changing one for it to take effect at once. Create the entries once with `auto-pass set`
(see `auto-pass set --help`); do not paste a PIN into a shell argument. After that, PINs change from the keypad's
Change PIN page.

## Surviving a reboot: the sealed key

Reading every PIN from the vault means every gated site answers 503 after a reboot until someone unlocks auto-pass,
including the auto-pass web page that could have unlocked it. **Sealed mode** removes that dependency while leaving
the vault locked.

- `scripts/seal_pin_key.sh` (run once with `sudo`) makes 32 random bytes and seals them to this machine's TPM2 with
  `systemd-creds` (PCR 7, the same policy ignition uses for the data volumes). The key is never written or printed
  in the clear.
- The gate then runs as a **system** unit (`config/systemd/wiring-harness-pin-gate.system.service.example`) running as
  your user, with `LoadCredentialEncrypted=`. systemd unseals the key at start and gives it to that service only.
- From it the gate derives a keyed fingerprint of each PIN, `HMAC(key, site|pin)`, and the cookie-signing key. The
  fingerprints live in the state file. They are not PINs and cannot be brute-forced offline without the TPM key.
- Whenever the vault is reachable (at start, hourly, and when a PIN changes) the gate refreshes the fingerprints from
  it. After that a locked vault no longer matters for unlocking: sites keep asking for their PIN and accept it.
- A PIN edited directly in the vault is noticed at the next refresh: its rotation clock restarts and its sessions end.
- **Changing a PIN still needs the vault unlocked**, because the vault is the source of truth. With it locked the
  page says the PIN is unchanged.
- No sealed key, or one that will not load, means the old behaviour: every check reads the vault.

What it does not do: anything running as your user while the gate runs could read the unsealed key, so this protects
against someone with the disk or a cold boot, not against code already running as you. The vault itself, and
everything else in it, is never exposed to the gate. It needs no more than the PIN entries it already has.

After a firmware update or a Secure Boot change the TPM will refuse the old key and the unit will not start (the
gated sites then stay closed). Re-seal with `sudo bash scripts/seal_pin_key.sh --force`, as for ignition's `--rebind`;
the fingerprints are rebuilt the next time the vault is unlocked, and until then the gate needs the vault again.

Sealing the PIN key makes the keypad available while the vault is locked, but it does not by itself make the Auto Pass
web backend start: that service normally fetches its own login token from the daemon. Pair this system unit with
Auto Pass's TPM-sealed web-token system unit. The coordinated, rollback-capable installer lives at
`../auto-pass/scripts/install_tpm_browser_unlock.sh`; run its `--dry-run` first. It seals only the gate key and web
login token. The KeePass master password remains interactive and is never stored in either credential.

## Changing a PIN

Every keypad has a **Change PIN** link to `/_pin/change` on the same site. It asks for the current PIN, the
new PIN and the new PIN again.

- The current PIN is checked first and counts toward the same site and IP lockouts as unlocking, so the form
  cannot be used to guess it.
- The new PIN must be four digits, entered identically twice, different from the current one, and not trivially
  guessable (repeated digits such as `0000`, or a straight run such as `1234` or `8765`). Rejected values write
  nothing and do not count as wrong guesses.
- The write goes to auto-pass through the daemon's scoped `set` operation, which only replaces the password of an
  entry that already exists. The gate reads the value back and reports a failure rather than trusting the write.
  On any failure the PIN is unchanged and the page says so.
- Cookies are tied to the PIN, so a successful change signs every other device out of that site; the browser that
  made the change gets a fresh cookie and stays unlocked.
- A change is announced through shock-relay on every channel. The message names the site and address, never a PIN.

This needs write access that `portfolio/pin/*` read access does not give. In auto-pass's local allowlist:

```toml
[repos.wiring-harness.vaults.infra]
allowed_paths  = ["portfolio/pin/*", "portfolio/pin-signing-key"]
writable_paths = ["portfolio/pin/*"]      # the signing key stays read-only
```

then restart and unlock the daemon so it loads the `set` operation (a write always needs the vault). Without `writable_paths` the page still opens
but a change fails with "unchanged".

## Rotation

PINs expire. The limit is **180 days** from the last change (`WH_PIN_ROTATE_DAYS`; 0 turns rotation off).

| Age | What happens |
|---|---|
| Under 150 days | nothing |
| Last 30 days (`WH_PIN_WARN_DAYS`) | after a correct PIN, a notice shows the days left with **Change PIN now** and **Remind me later**; one alert goes out through shock-relay |
| Past 180 days | the old PIN no longer opens the site. Entering it goes to the change page ("Your PIN has expired"), existing sessions end, and a second alert is sent. Changing the PIN restores access |

The check that sends alerts runs hourly inside the service, and each alert is sent once per PIN and phase.
`pin_gate.py status` lists every site's age and state.

The clock starts when the gate first sees a site and restarts on each change made through the Change PIN page, so a
PIN edited straight in the vault is not noticed. The ages live in the same owner-only state file as the lockouts;
`pin_gate.py reset` leaves them alone.

**Reuse.** The policy is that a PIN may not be reused, but for now the same PIN is allowed (`WH_PIN_ALLOW_REUSE`,
default on). A reused PIN writes nothing and just restarts the clock. Weak PINs such as `0000` are still refused,
including as a reused value, so the placeholder PINs must really change. Set `WH_PIN_ALLOW_REUSE=no` to enforce
the policy; only the current PIN is compared, with no history of older ones.

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

Without a journal (macOS, Windows) the gate writes an owner-only rotating file instead: `--log-file
{PATH|default|off}` or `WIRING_HARNESS_LOG_FILE`, on by default off Linux. `default` is
`~/Library/Logs/wiring-harness/pin-gate.log` on macOS, `%LOCALAPPDATA%\wiring-harness\Logs\pin-gate.log` on Windows and
`$XDG_STATE_HOME/wiring-harness/pin-gate.log` on Linux.

When the gate cannot read a secret it fails closed with a 503 whose text says why, and the log line carries the same
reason: `the auto-pass vault is locked`, `the auto-pass command was not found by the PIN gate` (a system unit has a
minimal `PATH`; the unit template adds `<home>/.local/bin`, and `serve` logs an error at start-up when `auto-pass` is not
on its `PATH`), `auto-pass refused the request`, or a generic `see the PIN gate log`.

## Limits

A PIN gates the HTTP surface only; it does not protect a backend reachable another way. A 4-digit PIN
without lockouts is not a secret, so do not run the gate with the limits raised to the point they do not bite.
