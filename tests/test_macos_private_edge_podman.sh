#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN_CONNECTION="${PODMAN_CONNECTION:-podman-machine-default}"
TEST_IMAGE="${TEST_IMAGE:-localhost/wiring-harness-macos-private-edge-test:local}"

podman --connection "${PODMAN_CONNECTION}" build \
  --tag "${TEST_IMAGE}" \
  --file "${REPO_ROOT}/tests/containers/macos-private-edge/Containerfile" \
  "${REPO_ROOT}"

podman --connection "${PODMAN_CONNECTION}" run \
  --rm \
  --network none \
  --cap-add NET_ADMIN \
  "${TEST_IMAGE}"
