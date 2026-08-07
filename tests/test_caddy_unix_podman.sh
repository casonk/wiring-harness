#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN_CONNECTION="${PODMAN_CONNECTION:-podman-machine-default}"
TEST_IMAGE="${TEST_IMAGE:-localhost/wiring-harness-caddy-unix-test:local}"

podman --connection "${PODMAN_CONNECTION}" build \
  --tag "${TEST_IMAGE}" \
  --file "${REPO_ROOT}/tests/containers/caddy-unix/Containerfile" \
  "${REPO_ROOT}"

podman --connection "${PODMAN_CONNECTION}" run --rm --network none "${TEST_IMAGE}"
