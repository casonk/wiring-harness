# macOS Air Device Profiles

`scripts/export_macos_air_profiles.py` creates Apple configuration profiles for
the temporary Air private edge. The default run issues one identity for `mini`
and a different identity for `pro`, both signed by the existing owner-only Air
CA under `~/.config/wiring-harness/certs/`.

The exporter is local and inert. It does not install profiles, import Keychain
material, change WireGuard, start a service, or use `sudo`.

## Generate or validate both profiles

Bootstrap the Air PKI first if it does not already exist, then export the two
device profiles:

```bash
python3 scripts/bootstrap_macos_air_pki.py
python3 scripts/export_macos_air_profiles.py
```

The second run validates every artifact and makes no byte changes. A partial,
tampered, wrong-owner, wrongly permissioned, or CA-incompatible profile set is
rejected rather than repaired or overwritten. Generation also requires the
live `certs/ca.crt` trust bundle consumed by Caddy to contain the exact Air root
exactly once; distinct legacy trust roots may remain alongside it.

To generate only one missing device, use `--device mini` or `--device pro`.
Existing complete identities are copied unchanged when another device is
added.

## Owner-only layout

The default output is:

```text
~/.config/wiring-harness/air-profiles/
├── air-ca.crt
├── manifest.json
├── profiles/
│   ├── air-mini.mobileconfig
│   └── air-pro.mobileconfig
└── identities/
    ├── mini/
    │   ├── client.crt
    │   ├── client.key
    │   ├── client.p12
    │   ├── client.p12.passphrase
    │   └── manifest.json
    └── pro/
        └── ...
```

Directories are mode `0700`; every file, including the public certificate and
manifests, is mode `0600`. Only the two `.mobileconfig` files are delivery
artifacts. Do not copy the `identities/` directory to a phone or shared folder.

Finder may add a mode-`0644` `.DS_Store` at the profile root or inside the
delivery-only `profiles/` directory. The exporter tolerates only that exact
current-user, regular, singly linked metadata file because every enclosing
directory remains mode `0700`; it is never treated as an artifact or copied
into a replacement profile set. Finder metadata in `identities/` or the source
PKI, unsafe links/types/modes, and every unknown file still fail closed.

An Apple configuration profile is not an encrypted archive. Each profile
contains the public Air root and an encrypted PKCS#12 identity, but deliberately
omits the PKCS#12 password. Treat the profile itself as sensitive and transfer
only the profile intended for that device.

## Install on Mini or Pro

1. Transfer only the matching file from `profiles/` to its iPhone and open it.
2. In Settings, open **Profile Downloaded** and install the profile.
3. When prompted for the identity password, copy the validated password to the
   Mac clipboard without printing it:

   ```bash
   python3 scripts/export_macos_air_profiles.py copy-passphrase --device mini
   python3 scripts/export_macos_air_profiles.py copy-passphrase --device pro
   ```

   Run only the command for the phone being installed, then paste through
   Universal Clipboard when available. The helper validates the complete
   profile set before feeding the password directly to `/usr/bin/pbcopy`.
   Universal Clipboard may retain and synchronize that password until it is
   overwritten. Clear the clipboard after installation without printing it:

   ```bash
   printf '' | /usr/bin/pbcopy
   ```
4. On the phone, open **Settings > General > About > Certificate Trust
   Settings** and enable full trust for **Air Temporary Edge CA** if iOS asks.
5. With that phone's WireGuard tunnel active, test the Air edge at
   `https://10.99.0.254:8443/` and `https://10.99.0.254:8444/`.

The profiles do not carry WireGuard configuration. Mini and Pro retain their
existing WireGuard profiles and receive only the Air HTTPS trust/identity
payloads here.

## Rotation and recovery

No identity is replaced unless `--rotate` is explicit:

```bash
python3 scripts/export_macos_air_profiles.py --device pro --rotate
```

The complete old profile set is retained in a timestamped owner-only sibling
backup before the replacement is installed. The source set must validate its
permissions, manifests, certificate/key pairing, PKCS#12 private key, subject,
EKU, and issuing chain even during rotation. Only a selected identity may waive
the 24-hour renewal window; an expired selected leaf is checked again with
certificate-time validation disabled so its signature, purpose, and key still
must be valid. Every preserved identity remains under strict time validation.
If the Air CA changed, rotate every existing device in one command; an
unselected old-CA identity is rejected.

Client-leaf rotation does **not** revoke the old certificate. The current Caddy
policy validates the issuing CA but has no leaf-certificate revocation list. A
previously exported leaf remains acceptable until it expires or the Air CA is
rotated and the edge is deliberately reloaded with the new trust anchor. Use a
full CA rotation and reissue every device if an old identity may be compromised.

The generated mobileconfig UUIDs are stable per device and payload role so a
rotated profile replaces the prior Mini or Pro profile cleanly instead of
accumulating a second logical profile.
