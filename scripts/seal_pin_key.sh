#!/usr/bin/env bash
# seal_pin_key.sh — create the TPM-sealed key the PIN gate uses to check PINs while the vault is locked.
#
# Generates 32 random bytes and encrypts them with systemd-creds, bound to this machine's TPM2 (PCR 7,
# Secure Boot state, the same policy ignition uses for the LUKS volumes). The plaintext key is never
# written to disk or printed. Run as root; the gate's system unit loads the result with
# LoadCredentialEncrypted= and systemd unseals it for that service only.
#
# Usage: sudo bash scripts/seal_pin_key.sh [--force] [--output FILE]
#   --force        replace an existing sealed key (every stored fingerprint is then rebuilt from the
#                  vault the next time it is unlocked)
#   --output FILE  default /etc/credstore.encrypted/wiring-harness-pin-seal-key
set -euo pipefail

OUTPUT=/etc/credstore.encrypted/wiring-harness-pin-seal-key
NAME=pin-seal-key # must match the LoadCredentialEncrypted= id in the unit
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1 ;;
    --output)
      OUTPUT="${2:?--output needs a file}"
      shift
      ;;
    -h | --help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      echo "error: unknown option $1" >&2
      exit 2
      ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || {
  echo "error: run with sudo" >&2
  exit 1
}
command -v systemd-creds > /dev/null || {
  echo "error: systemd-creds not found" >&2
  exit 1
}

if [[ -e "$OUTPUT" && $FORCE -ne 1 ]]; then
  echo "error: $OUTPUT exists; use --force to replace it" >&2
  exit 1
fi

install -d -m 0755 "$(dirname "$OUTPUT")"
tmp="$(mktemp "$(dirname "$OUTPUT")/.pin-seal.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# The key goes from the random source straight into systemd-creds on a pipe.
head -c 32 /dev/urandom | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name="$NAME" - "$tmp"
chmod 0600 "$tmp"

# Prove the TPM can open it before committing, without showing the key.
size="$(systemd-creds decrypt --name="$NAME" "$tmp" - | wc -c)"
if [[ "$size" -ne 32 ]]; then
  echo "error: sealed key did not decrypt to 32 bytes (got $size); nothing installed" >&2
  exit 1
fi

mv -f "$tmp" "$OUTPUT"
trap - EXIT
echo "sealed key installed: $OUTPUT (32 bytes, TPM2 PCR 7)"
