#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SETUP_SCRIPT="${SCRIPT_DIR}/setup.sh"

VORCARO_DATA_DIR="${VORCARO_DATA_DIR:-/var/lib/vorcaro}"
VORCARO_CERT_DIR="${VORCARO_CERT_DIR:-/etc/vorcaro/certs}"
VORCARO_SECRET_DIR="${VORCARO_SECRET_DIR:-/etc/vorcaro/secrets}"
VORCARO_SERVICE_UID="${VORCARO_SERVICE_UID:-10001}"
VORCARO_SERVICE_GID="${VORCARO_SERVICE_GID:-10001}"
VORCARO_CERT_DAYS="${VORCARO_CERT_DAYS:-825}"
VORCARO_CA_DAYS="${VORCARO_CA_DAYS:-3650}"
VORCARO_FORCE="${VORCARO_FORCE:-0}"

ROOT_CA_KEY="${VORCARO_CERT_DIR}/root-ca.key.pem"
ROOT_CA_CERT="${VORCARO_CERT_DIR}/root-ca.pem"
DEVICE_CLIENT_CA_KEY="${VORCARO_CERT_DIR}/device-client-ca.key.pem"
DEVICE_CLIENT_CA_CERT="${VORCARO_CERT_DIR}/device-client-ca.pem"
ADMIN_CLIENT_CA_KEY="${VORCARO_CERT_DIR}/admin-client-ca.key.pem"
ADMIN_CLIENT_CA_CERT="${VORCARO_CERT_DIR}/admin-client-ca.pem"
SERVER_SIGNING_KEY="${VORCARO_SECRET_DIR}/server-signing.key"

main() {
  require_root
  ensure_dependencies

  create_layout
  generate_ca "${ROOT_CA_KEY}" "${ROOT_CA_CERT}" "/O=Vorcaro Enterprises/CN=Vorcaro Local Root CA"
  generate_ca "${DEVICE_CLIENT_CA_KEY}" "${DEVICE_CLIENT_CA_CERT}" "/O=Vorcaro Enterprises/CN=Vorcaro Local Device Client CA"
  generate_ca "${ADMIN_CLIENT_CA_KEY}" "${ADMIN_CLIENT_CA_CERT}" "/O=Vorcaro Enterprises/CN=Vorcaro Local Admin Client CA"
  generate_server_cert "device-server" "${ROOT_CA_KEY}" "${ROOT_CA_CERT}" "device.local.vorcaro"
  generate_server_cert "admin-server" "${ROOT_CA_KEY}" "${ROOT_CA_CERT}" "admin.local.vorcaro"
  generate_client_cert "bootstrap-device-client" "${DEVICE_CLIENT_CA_KEY}" "${DEVICE_CLIENT_CA_CERT}" "Vorcaro Bootstrap Device Client"
  generate_client_cert "bootstrap-admin-client" "${ADMIN_CLIENT_CA_KEY}" "${ADMIN_CLIENT_CA_CERT}" "Vorcaro Bootstrap Admin Client"
  generate_client_cert "healthcheck-client" "${ADMIN_CLIENT_CA_KEY}" "${ADMIN_CLIENT_CA_CERT}" "Vorcaro Healthcheck Client"
  generate_server_signing_key
  initialize_databases_if_possible
  set_permissions
  print_summary
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "server/bootstrap.sh must be run as root." >&2
    exit 1
  fi
}

ensure_dependencies() {
  local missing=""

  if ! command -v openssl >/dev/null 2>&1; then
    missing="${missing} openssl"
  fi
  if ! command -v node >/dev/null 2>&1; then
    missing="${missing} node"
  elif ! node_version_supported; then
    missing="${missing} node>=22"
  fi
  if ! command -v pnpm >/dev/null 2>&1; then
    missing="${missing} pnpm"
  elif ! pnpm_version_supported; then
    missing="${missing} pnpm>=10"
  fi
  if ! command -v docker >/dev/null 2>&1; then
    missing="${missing} docker"
  elif ! docker compose version >/dev/null 2>&1; then
    missing="${missing} docker-compose"
  fi

  if [ -n "${missing}" ]; then
    if [ ! -x "${SETUP_SCRIPT}" ]; then
      echo "Missing dependencies:${missing}" >&2
      echo "Expected executable installer at ${SETUP_SCRIPT}" >&2
      exit 1
    fi

    echo "Missing dependencies:${missing}"
    echo "Running ${SETUP_SCRIPT}"
    "${SETUP_SCRIPT}"
  fi

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
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

node_version_supported() {
  [ "$(node -p 'Number(process.versions.node.split(".")[0])')" -ge 22 ]
}

pnpm_version_supported() {
  [ "$(pnpm --version | cut -d. -f1)" -ge 10 ]
}

require_node_version() {
  if ! node_version_supported; then
    echo "Node.js 22 or newer is required." >&2
    exit 1
  fi
}

require_pnpm_version() {
  if ! pnpm_version_supported; then
    echo "pnpm 10 or newer is required." >&2
    exit 1
  fi
}

require_docker_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required." >&2
    exit 1
  fi
}

create_layout() {
  install -d -m 0750 -o "${VORCARO_SERVICE_UID}" -g "${VORCARO_SERVICE_GID}" "${VORCARO_DATA_DIR}"
  install -d -m 0750 -o "${VORCARO_SERVICE_UID}" -g "${VORCARO_SERVICE_GID}" "${VORCARO_DATA_DIR}/backups"
  install -d -m 0750 -o "${VORCARO_SERVICE_UID}" -g "${VORCARO_SERVICE_GID}" "${VORCARO_CERT_DIR}"
  install -d -m 0750 -o "${VORCARO_SERVICE_UID}" -g "${VORCARO_SERVICE_GID}" "${VORCARO_SECRET_DIR}"
}

generate_ca() {
  local key_file="$1"
  local cert_file="$2"
  local subject="$3"

  if should_skip_pair "${key_file}" "${cert_file}"; then
    echo "Keeping existing CA: ${cert_file}"
    return
  fi

  rm_if_forced "${key_file}" "${cert_file}"
  openssl req \
    -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -days "${VORCARO_CA_DAYS}" \
    -nodes \
    -keyout "${key_file}" \
    -out "${cert_file}" \
    -subj "${subject}" >/dev/null 2>&1
}

generate_server_cert() {
  local name="$1"
  local ca_key="$2"
  local ca_cert="$3"
  local cn="$4"
  local key_file="${VORCARO_CERT_DIR}/${name}.key.pem"
  local cert_file="${VORCARO_CERT_DIR}/${name}.cert.pem"
  local csr_file
  local ext_file

  if should_skip_pair "${key_file}" "${cert_file}"; then
    echo "Keeping existing server certificate: ${cert_file}"
    return
  fi

  csr_file="$(mktemp)"
  ext_file="$(mktemp)"
  rm_if_forced "${key_file}" "${cert_file}"
  cat >"${ext_file}" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,DNS:${cn},IP:127.0.0.1
EOF
  openssl req \
    -new \
    -newkey rsa:3072 \
    -nodes \
    -keyout "${key_file}" \
    -out "${csr_file}" \
    -subj "/O=Vorcaro Enterprises/CN=${cn}" >/dev/null 2>&1
  openssl x509 \
    -req \
    -in "${csr_file}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${cert_file}" \
    -days "${VORCARO_CERT_DAYS}" \
    -sha256 \
    -extfile "${ext_file}" >/dev/null 2>&1
  rm -f "${csr_file}" "${ext_file}"
}

generate_client_cert() {
  local name="$1"
  local ca_key="$2"
  local ca_cert="$3"
  local cn="$4"
  local key_file="${VORCARO_CERT_DIR}/${name}.key.pem"
  local cert_file="${VORCARO_CERT_DIR}/${name}.cert.pem"
  local csr_file
  local ext_file

  if should_skip_pair "${key_file}" "${cert_file}"; then
    echo "Keeping existing client certificate: ${cert_file}"
    return
  fi

  csr_file="$(mktemp)"
  ext_file="$(mktemp)"
  rm_if_forced "${key_file}" "${cert_file}"
  cat >"${ext_file}" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
  openssl req \
    -new \
    -newkey rsa:3072 \
    -nodes \
    -keyout "${key_file}" \
    -out "${csr_file}" \
    -subj "/O=Vorcaro Enterprises/CN=${cn}" >/dev/null 2>&1
  openssl x509 \
    -req \
    -in "${csr_file}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${cert_file}" \
    -days "${VORCARO_CERT_DAYS}" \
    -sha256 \
    -extfile "${ext_file}" >/dev/null 2>&1
  rm -f "${csr_file}" "${ext_file}"
}

generate_server_signing_key() {
  if [ -f "${SERVER_SIGNING_KEY}" ] && [ "${VORCARO_FORCE}" != "1" ]; then
    echo "Keeping existing server signing key: ${SERVER_SIGNING_KEY}"
    return
  fi

  ensure_protocol_build
  rm_if_forced "${SERVER_SIGNING_KEY}"
  PROTOCOL_DIST="${REPO_ROOT}/packages/protocol/dist/src/index.js" node --input-type=module >"${SERVER_SIGNING_KEY}" <<'NODE'
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

const protocol = await import(pathToFileURL(process.env.PROTOCOL_DIST).href);
process.stdout.write(`${protocol.deriveSigningKeyPair(randomBytes(32)).secretKey}\n`);
NODE
}

ensure_protocol_build() {
  if [ -f "${REPO_ROOT}/packages/protocol/dist/src/index.js" ]; then
    return
  fi

  if ! command -v pnpm >/dev/null 2>&1; then
    echo "Protocol package is not built and pnpm is not available." >&2
    echo "Run pnpm install && pnpm build, then rerun server/bootstrap.sh." >&2
    exit 1
  fi

  (
    cd "${REPO_ROOT}"
    COREPACK_HOME="${COREPACK_HOME:-/tmp/vorcaro-corepack}" \
      PNPM_HOME="${PNPM_HOME:-/tmp/vorcaro-pnpm}" \
      pnpm --filter @vorcaro/protocol build
  )
}

initialize_databases_if_possible() {
  if [ ! -f "${REPO_ROOT}/server/dist/db/sqlite.js" ]; then
    echo "Server dist not found; databases will be initialized by the first container start."
    return
  fi

  DATA_DIR="${VORCARO_DATA_DIR}" SERVER_DB_MODULE="${REPO_ROOT}/server/dist/db/sqlite.js" node --input-type=module <<'NODE'
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const db = await import(pathToFileURL(process.env.SERVER_DB_MODULE).href);
const ledger = db.openLedgerDatabase({ path: join(process.env.DATA_DIR, "ledger.db") });
const projections = db.openProjectionsDatabase({ path: join(process.env.DATA_DIR, "projections.db") });
ledger.close();
projections.close();
NODE
}

set_permissions() {
  chown -R "${VORCARO_SERVICE_UID}:${VORCARO_SERVICE_GID}" "${VORCARO_DATA_DIR}" "${VORCARO_CERT_DIR}" "${VORCARO_SECRET_DIR}"
  chmod 0750 "${VORCARO_DATA_DIR}" "${VORCARO_DATA_DIR}/backups" "${VORCARO_CERT_DIR}" "${VORCARO_SECRET_DIR}"
  find "${VORCARO_CERT_DIR}" -type f -name "*.key.pem" -exec chmod 0400 {} \;
  find "${VORCARO_CERT_DIR}" -type f -name "*.pem" ! -name "*.key.pem" -exec chmod 0444 {} \;
  find "${VORCARO_SECRET_DIR}" -type f -exec chmod 0400 {} \;
  find "${VORCARO_DATA_DIR}" -type f -exec chmod 0600 {} \;
}

should_skip_pair() {
  [ -f "$1" ] && [ -f "$2" ] && [ "${VORCARO_FORCE}" != "1" ]
}

rm_if_forced() {
  if [ "${VORCARO_FORCE}" = "1" ]; then
    rm -f "$@"
  fi
}

print_summary() {
  cat <<EOF

Vorcaro bootstrap complete.

Data directory:   ${VORCARO_DATA_DIR}
Certificate dir:  ${VORCARO_CERT_DIR}
Secret dir:       ${VORCARO_SECRET_DIR}
Runtime UID/GID:  ${VORCARO_SERVICE_UID}:${VORCARO_SERVICE_GID}

Next command:
  docker compose up -d

Local admin status probe:
  curl --cert ${VORCARO_CERT_DIR}/bootstrap-admin-client.cert.pem \\
       --key ${VORCARO_CERT_DIR}/bootstrap-admin-client.key.pem \\
       --cacert ${ROOT_CA_CERT} \\
       https://localhost:9443/admin/v1/status

Existing files were preserved. Set VORCARO_FORCE=1 to regenerate bootstrap
certificates and the server signing key.
EOF
}

main "$@"
