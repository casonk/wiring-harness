#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_SNOWBRIDGE_REPO="${REPO_ROOT}/../snowbridge"
DEFAULT_IMAGE="localhost/filebrowser-snowbridge:dirsize"
SERVICE_NAME="filebrowser"

SNOWBRIDGE_REPO="${DEFAULT_SNOWBRIDGE_REPO}"
IMAGE="${DEFAULT_IMAGE}"
CONTAINER_TOOL=""
ENV_FILE=""
COMPOSE_FILE=""
ENV_EXAMPLE=""
BUILD_SCRIPT=""
SKIP_BUILD=0
PULL_BASE=0
NO_CACHE=0
PUSH_IMAGE=0
DRY_RUN=0
COMPOSE_CMD=()
COMPOSE_CMD_TEXT=""

usage() {
  cat <<'EOF'
Usage: deploy_snowbridge_filebrowser_fork_image.sh [options]

Build Snowbridge's patched File Browser image, write the chosen image tag into
Snowbridge's local env file, and recreate only the backend `filebrowser`
service. Shared host Caddy remains managed by wiring-harness.

Options:
  --snowbridge-repo PATH      Snowbridge repo path. Default: ../snowbridge
  --env-file PATH             Snowbridge env file to update. Default: config/web/filebrowser/filebrowser.env.local
  --compose-file PATH         Snowbridge compose file. Default: config/web/filebrowser/docker-compose.example.yml
  --image NAME[:TAG]          Image tag to deploy. Default: localhost/filebrowser-snowbridge:dirsize
  --container-tool TOOL       Build image with `podman` or `docker`. Auto-detected when omitted.
  --skip-build                Reuse an already-built image tag and only update env + recreate.
  --pull                      Ask the container builder to refresh base images.
  --no-cache                  Disable the container build cache.
  --push                      Push the image after building it.
  --dry-run                   Print commands without executing them.
  --help                      Show this help text.

Notes:
  - This helper expects Snowbridge's fork workspace setup to live in the
    sibling `snowbridge` repo and reuses that repo's existing image builder.
  - It does not touch host Caddy. If you changed services.toml, certs,
    hostnames, or ports, run `sudo python3 scripts/setup_caddy.py --provision`
    separately after the backend deploy.

Typical flow:
  ./scripts/deploy_snowbridge_filebrowser_fork_image.sh
  ./scripts/deploy_snowbridge_filebrowser_fork_image.sh --skip-build
EOF
}

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

print_cmd() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
}

run_cmd() {
  if (( DRY_RUN )); then
    print_cmd "$@"
    return 0
  fi
  "$@"
}

run_privileged_cmd() {
  if (( DRY_RUN )); then
    if [[ "${EUID}" -eq 0 ]]; then
      print_cmd "$@"
    else
      print_cmd sudo "$@"
    fi
    return 0
  fi

  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
    return 0
  fi

  command_exists sudo || fail "sudo is required for image build and backend recreation"
  sudo "$@"
}

docker_is_podman_wrapper() {
  command_exists docker || return 1
  docker --help 2>&1 | grep -q 'Emulate Docker CLI using podman'
}

docker_compose_available() {
  command_exists docker && docker compose version >/dev/null 2>&1
}

docker_compose_legacy_available() {
  command_exists docker-compose && docker-compose version >/dev/null 2>&1
}

podman_compose_available() {
  command_exists podman-compose && podman-compose version >/dev/null 2>&1
}

set_compose_command() {
  if podman_compose_available && (command_exists podman || docker_is_podman_wrapper); then
    COMPOSE_CMD=(podman-compose)
    COMPOSE_CMD_TEXT="podman-compose"
    return 0
  fi

  if docker_compose_available; then
    COMPOSE_CMD=(docker compose)
    COMPOSE_CMD_TEXT="docker compose"
    return 0
  fi

  if docker_compose_legacy_available; then
    COMPOSE_CMD=(docker-compose)
    COMPOSE_CMD_TEXT="docker-compose"
    return 0
  fi

  if podman_compose_available; then
    COMPOSE_CMD=(podman-compose)
    COMPOSE_CMD_TEXT="podman-compose"
    return 0
  fi

  if (( DRY_RUN )); then
    COMPOSE_CMD=(podman-compose)
    COMPOSE_CMD_TEXT="podman-compose (dry-run fallback)"
    return 0
  fi

  fail "no supported Compose frontend found; install podman-compose, docker compose, or docker-compose"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --snowbridge-repo)
        [[ $# -ge 2 ]] || fail "--snowbridge-repo requires a path"
        SNOWBRIDGE_REPO="$2"
        shift 2
        ;;
      --env-file)
        [[ $# -ge 2 ]] || fail "--env-file requires a path"
        ENV_FILE="$2"
        shift 2
        ;;
      --compose-file)
        [[ $# -ge 2 ]] || fail "--compose-file requires a path"
        COMPOSE_FILE="$2"
        shift 2
        ;;
      --image)
        [[ $# -ge 2 ]] || fail "--image requires a tag"
        IMAGE="$2"
        shift 2
        ;;
      --container-tool)
        [[ $# -ge 2 ]] || fail "--container-tool requires podman or docker"
        CONTAINER_TOOL="$2"
        shift 2
        ;;
      --skip-build)
        SKIP_BUILD=1
        shift
        ;;
      --pull)
        PULL_BASE=1
        shift
        ;;
      --no-cache)
        NO_CACHE=1
        shift
        ;;
      --push)
        PUSH_IMAGE=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

configure_paths() {
  [[ -d "${SNOWBRIDGE_REPO}" ]] || fail "snowbridge repo not found: ${SNOWBRIDGE_REPO}"
  SNOWBRIDGE_REPO="$(cd "${SNOWBRIDGE_REPO}" && pwd)"

  BUILD_SCRIPT="${SNOWBRIDGE_REPO}/scripts/build_filebrowser_fork_image.sh"
  ENV_EXAMPLE="${ENV_EXAMPLE:-${SNOWBRIDGE_REPO}/config/web/filebrowser/filebrowser.env.example}"
  ENV_FILE="${ENV_FILE:-${SNOWBRIDGE_REPO}/config/web/filebrowser/filebrowser.env.local}"
  COMPOSE_FILE="${COMPOSE_FILE:-${SNOWBRIDGE_REPO}/config/web/filebrowser/docker-compose.example.yml}"
}

ensure_paths_exist() {
  [[ -x "${BUILD_SCRIPT}" ]] || fail "Snowbridge build helper not found or not executable: ${BUILD_SCRIPT}"
  [[ -f "${ENV_EXAMPLE}" ]] || fail "Snowbridge env example not found: ${ENV_EXAMPLE}"
  [[ -f "${COMPOSE_FILE}" ]] || fail "Snowbridge compose file not found: ${COMPOSE_FILE}"
}

ensure_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    return 0
  fi

  log "initialize missing Snowbridge env file from example"

  if (( DRY_RUN )); then
    print_cmd install -D -m 0644 "${ENV_EXAMPLE}" "${ENV_FILE}"
    return 0
  fi

  if install -D -m 0644 "${ENV_EXAMPLE}" "${ENV_FILE}" 2>/dev/null; then
    return 0
  fi

  run_privileged_cmd install -D -m 0644 "${ENV_EXAMPLE}" "${ENV_FILE}"
}

replace_env_setting() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp

  if [[ ! -f "${file}" ]]; then
    if (( DRY_RUN )); then
      return 0
    fi
    fail "env file not found: ${file}"
  fi

  if (( DRY_RUN )); then
    return 0
  fi

  if [[ ! -r "${file}" || ! -w "${file}" ]]; then
    run_privileged_cmd /bin/bash -c '
      file="$1"
      key="$2"
      value="$3"
      tmp="$(mktemp)"
      awk -v key="${key}" -v value="${value}" "
        BEGIN { updated = 0 }
        index(\$0, key \"=\") == 1 {
          print key \"=\" value
          updated = 1
          next
        }
        { print }
        END {
          if (!updated) {
            print key \"=\" value
          }
        }
      " "${file}" > "${tmp}"
      install -m "$(stat -c "%a" "${file}")" -o "$(stat -c "%u" "${file}")" -g "$(stat -c "%g" "${file}")" "${tmp}" "${file}"
      rm -f "${tmp}"
    ' _ "${file}" "${key}" "${value}"
    return 0
  fi

  tmp="$(mktemp)"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' "${file}" > "${tmp}"
  install -m "$(stat -c "%a" "${file}")" "${tmp}" "${file}"
  rm -f "${tmp}"
}

build_image() {
  local args=("${BUILD_SCRIPT}" --image "${IMAGE}")

  if [[ -n "${CONTAINER_TOOL}" ]]; then
    args+=(--container-tool "${CONTAINER_TOOL}")
  fi

  if (( PULL_BASE )); then
    args+=(--pull)
  fi

  if (( NO_CACHE )); then
    args+=(--no-cache)
  fi

  if (( PUSH_IMAGE )); then
    args+=(--push)
  fi

  if (( DRY_RUN )); then
    args+=(--dry-run)
  fi

  log "build Snowbridge File Browser fork image"
  run_privileged_cmd "${args[@]}"
}

run_compose_with_env() {
  local action="$1"
  shift
  local -a args=("$@")

  if (( DRY_RUN )); then
    log "use environment from ${ENV_FILE}"
    if [[ "${EUID}" -eq 0 ]]; then
      print_cmd "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" "${args[@]}"
    else
      print_cmd sudo "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" "${args[@]}"
    fi
    return 0
  fi

  run_privileged_cmd /bin/bash -lc '
    set -euo pipefail
    env_file="$1"
    shift
    set -a
    source "${env_file}"
    set +a
    "$@"
  ' _ "${ENV_FILE}" "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" "${args[@]}"

  log "${action}"
}

update_env_file() {
  if (( DRY_RUN )); then
    log "planned FILEBROWSER_IMAGE=${IMAGE} update in ${ENV_FILE}"
    return 0
  fi

  replace_env_setting "${ENV_FILE}" "FILEBROWSER_IMAGE" "${IMAGE}"
  log "updated FILEBROWSER_IMAGE in ${ENV_FILE}"
}

main() {
  parse_args "$@"
  configure_paths
  ensure_paths_exist

  if (( SKIP_BUILD == 0 )); then
    build_image
  fi

  ensure_env_file
  update_env_file
  set_compose_command
  run_compose_with_env "validated ${COMPOSE_CMD_TEXT} configuration" config
  run_compose_with_env "recreated Snowbridge ${SERVICE_NAME} backend service" up -d --force-recreate "${SERVICE_NAME}"

  log "next checks:"
  log "  - open https://files.snowbridge.internal through the shared wiring-harness Caddy"
  log "  - if hostnames, certs, or backend port changed, run sudo python3 scripts/setup_caddy.py --provision"
}

main "$@"
