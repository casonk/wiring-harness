# Security Policy

## Reporting

Do not file sensitive disclosures in public issues.

For this repository, security-sensitive reports should be handled privately by the repository owner.

## Scope

- Do not commit generated certificates, private keys, PKCS12 bundles, or passphrases.
- Do not commit machine-specific absolute filesystem paths, mount points, usernames, hostnames, or other unnecessary local-environment identifiers unless strictly required.
- Do not include credentials, local-only tokens, or personal data in issues or pull requests.
- Treat `CHATHISTORY.md` as local-only operational memory.
- Treat local auth state, device codes, and session-specific output as sensitive operational context.

## Safe Documentation Practices

- Generated files (certs, keys, mobileconfigs) belong in `~/.config/wiring-harness/` or `/srv/snowbridge/share/tmp/` — never in the repository.
- Use relative references in committed docs where sufficient.
- Keep durable operational guidance in tracked docs such as `AGENTS.md` and `LESSONSLEARNED.md`.
- Keep transient workflow notes in local-only `CHATHISTORY.md`.
