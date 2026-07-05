#!/usr/bin/env bash
set -euo pipefail

REQUIRED_PNPM_VERSION="10.12.1"
VORCARO_DATA_DIR="${VORCARO_DATA_DIR:-/var/lib/vorcaro}"
VORCARO_CERT_DIR="${VORCARO_CERT_DIR:-/etc/vorcaro/certs}"
VORCARO_SECRET_DIR="${VORCARO_SECRET_DIR:-/etc/vorcaro/secrets}"
VORCARO_SERVICE_UID="${VORCARO_SERVICE_UID:-10001}"
VORCARO_SERVICE_GID="${VORCARO_SERVICE_GID:-10001}"

main() {
  require_root
  prepare_host_layout
  install_system_packages
  install_pnpm
  start_docker_if_possible
  verify_installed_dependencies
  print_summary
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "server/setup.sh must be run as root." >&2
    exit 1
  fi
}

prepare_host_layout() {
  mkdir -p "${VORCARO_DATA_DIR}" "${VORCARO_CERT_DIR}" "${VORCARO_SECRET_DIR}"
  chown -R "${VORCARO_SERVICE_UID}:${VORCARO_SERVICE_GID}" \
    "${VORCARO_DATA_DIR}" \
    "$(dirname "${VORCARO_CERT_DIR}")" \
    "$(dirname "${VORCARO_SECRET_DIR}")"
  chmod 0750 \
    "${VORCARO_DATA_DIR}" \
    "$(dirname "${VORCARO_CERT_DIR}")" \
    "$(dirname "${VORCARO_SECRET_DIR}")" \
    "${VORCARO_CERT_DIR}" \
    "${VORCARO_SECRET_DIR}"
}

install_system_packages() {
  case "$(detect_platform)" in
    apt)
      apt_install
      ;;
    dnf)
      dnf install -y openssl nodejs npm docker docker-compose-plugin
      ;;
    yum)
      yum install -y openssl nodejs npm docker docker-compose-plugin
      ;;
    apk)
      apk add --no-cache openssl nodejs npm docker docker-cli-compose
      ;;
    pacman)
      pacman -Sy --noconfirm openssl nodejs npm docker docker-compose
      ;;
    zypper)
      zypper --non-interactive install openssl nodejs npm docker docker-compose
      ;;
    darwin)
      echo "macOS package installation is not automated from this root script."
      echo "Install Node.js 22, pnpm 10, OpenSSL, and Docker Desktop if they are missing."
      ;;
    *)
      echo "Unsupported platform. Install Node.js 22, pnpm 10, OpenSSL, Docker, and Docker Compose v2 manually." >&2
      exit 1
      ;;
  esac
}

detect_platform() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "darwin"
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "yum"
    return
  fi
  if command -v apk >/dev/null 2>&1; then
    echo "apk"
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    echo "pacman"
    return
  fi
  if command -v zypper >/dev/null 2>&1; then
    echo "zypper"
    return
  fi
  echo "unknown"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates openssl nodejs npm docker.io
  if apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    apt-get install -y docker-compose-plugin
  else
    echo "The apt repository does not provide docker-compose-plugin." >&2
    echo "Install Docker Compose v2 from an approved repository, then rerun server/bootstrap.sh." >&2
    exit 1
  fi
}

install_pnpm() {
  if command -v corepack >/dev/null 2>&1; then
    corepack enable
    corepack prepare "pnpm@${REQUIRED_PNPM_VERSION}" --activate
  fi

  if ! command -v pnpm >/dev/null 2>&1; then
    if ! command -v npm >/dev/null 2>&1; then
      echo "npm is required to install pnpm when corepack is unavailable." >&2
      exit 1
    fi
    npm install -g "pnpm@${REQUIRED_PNPM_VERSION}"
  fi
}

start_docker_if_possible() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    return
  fi

  if command -v service >/dev/null 2>&1; then
    service docker start >/dev/null 2>&1 || true
  fi
}

verify_installed_dependencies() {
  require_command openssl
  require_command node
  require_command pnpm
  require_command docker
  require_node_version
  require_pnpm_version
  require_docker_compose
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command after setup: $1" >&2
    exit 1
  fi
}

require_node_version() {
  if [ "$(node -p 'Number(process.versions.node.split(".")[0])')" -lt 22 ]; then
    echo "Node.js 22 or newer is required. The OS package manager installed $(node --version)." >&2
    exit 1
  fi
}

require_pnpm_version() {
  if [ "$(pnpm --version | cut -d. -f1)" -lt 10 ]; then
    echo "pnpm 10 or newer is required. Installed version: $(pnpm --version)." >&2
    exit 1
  fi
}

require_docker_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required." >&2
    exit 1
  fi
}

print_summary() {
  cat <<EOF

Vorcaro server dependencies are installed.

Host layout:
  data:    ${VORCARO_DATA_DIR}
  certs:   ${VORCARO_CERT_DIR}
  secrets: ${VORCARO_SECRET_DIR}
  owner:   ${VORCARO_SERVICE_UID}:${VORCARO_SERVICE_GID}

Required runtime tools:
  node:    $(node --version)
  pnpm:    $(pnpm --version)
  openssl: $(openssl version | cut -d' ' -f1-2)
  docker:  $(docker --version)
  compose: $(docker compose version)

Next command:
  sudo server/bootstrap.sh
EOF
}

main "$@"
