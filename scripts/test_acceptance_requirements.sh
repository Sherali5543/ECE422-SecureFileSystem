#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export LANG=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
SCHEMA_PATH="${ROOT_DIR}/server/db/init/001-schema.sql"
CERT_PATH="${ROOT_DIR}/server/deploy/secrets/server-cert.pem"
KEY_PATH="${ROOT_DIR}/server/deploy/secrets/server-key.pem"

HOST="${HOST:-localhost}"
PORT="${PORT:-9443}"
STRICT="${STRICT:-0}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sfs-acceptance.XXXXXX")"
DB_PATH="${DB_PATH:-${TMP_DIR}/sfs.db}"
STORAGE_ROOT="${STORAGE_ROOT:-${TMP_DIR}/storage}"
SERVER_LOG="${TMP_DIR}/server.log"
ALICE_READ_OUT="${TMP_DIR}/alice_read.out"
CORRUPT_READ_OUT="${TMP_DIR}/corrupt_read.out"
ALICE_REGISTER_LOG="${TMP_DIR}/alice_register.log"
BOB_REGISTER_LOG="${TMP_DIR}/bob_register.log"
ALICE_FLOW_LOG="${TMP_DIR}/alice_flow.log"
BOB_FLOW_LOG="${TMP_DIR}/bob_flow.log"
CORRUPT_FLOW_LOG="${TMP_DIR}/corrupt_flow.log"

SERVER_PID=""

REQ1_STATUS="FAIL"
REQ2_STATUS="FAIL"
REQ3_STATUS="FAIL"
REQ4_STATUS="FAIL"
REQ5_STATUS="FAIL"
REQ6_STATUS="FAIL"
REQ7_STATUS="FAIL"

REQ1_NOTE=""
REQ2_NOTE=""
REQ3_NOTE=""
REQ4_NOTE=""
REQ5_NOTE=""
REQ6_NOTE=""
REQ7_NOTE=""

cleanup() {
  local exit_code=$?

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi

  if [[ "${exit_code}" -ne 0 || "${KEEP_TMP:-0}" == "1" ]]; then
    echo "Preserving temp artifacts in ${TMP_DIR}" >&2
  else
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Missing required file: ${path}" >&2
    exit 1
  fi
}

set_req() {
  local req="$1"
  local status="$2"
  local note="$3"

  printf -v "REQ${req}_STATUS" '%s' "${status}"
  printf -v "REQ${req}_NOTE" '%s' "${note}"
}

assert_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "Assertion failed: expected '${expected}' in ${file}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq -- "${unexpected}" "${file}"; then
    echo "Assertion failed: unexpected '${unexpected}' in ${file}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

run_client_flow() {
  local outfile="$1"
  local input="$2"

  printf '%s' "${input}" | \
    CA_CERT="${CERT_PATH}" SERVER_ADDR="${HOST}" SERVER_PORT="${PORT}" \
    "${BUILD_DIR}/client/client" >"${outfile}" 2>&1
}

build_project() {
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" >/dev/null
  cmake --build "${BUILD_DIR}" >/dev/null
}

start_server() {
  mkdir -p "$(dirname "${DB_PATH}")" "${STORAGE_ROOT}"
  sqlite3 "${DB_PATH}" < "${SCHEMA_PATH}"

  DB_PATH="${DB_PATH}" \
  DB_SCHEMA="${SCHEMA_PATH}" \
  STORAGE_ROOT="${STORAGE_ROOT}" \
  SERVER_CERT="${CERT_PATH}" \
  SERVER_KEY="${KEY_PATH}" \
  PORT="${PORT}" \
  "${BUILD_DIR}/server/server" >"${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!

  sleep 1
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "Server failed to stay up. Log follows:" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
  fi
}

run_register_tests() {
  echo "[1/5] Registering users"
  run_client_flow "${ALICE_REGISTER_LOG}" $'register\nalice\nalicepass\nexit\n'
  assert_contains "${ALICE_REGISTER_LOG}" "Registered user 'alice'"

  run_client_flow "${BOB_REGISTER_LOG}" $'register\nbob\nbobpass\nexit\n'
  assert_contains "${BOB_REGISTER_LOG}" "Registered user 'bob'"

  set_req 1 "PASS" "users can be created through the client register flow"
}

run_alice_flow() {
  echo "[2/5] Running Alice CLI flow"
  run_client_flow "${ALICE_FLOW_LOG}" "$(cat <<EOF
login
alice
alicepass
pwd
mkdir docs
create docs/a.bin
write ${ROOT_DIR}/README.md docs/a.bin
read docs/a.bin ${ALICE_READ_OUT}
mv docs/a.bin docs/a2.bin
ls docs
group-create devs
group-add devs bob
group-list
create docs/shared.bin devs
write ${ROOT_DIR}/README.md docs/shared.bin
chmod 0200 docs/a2.bin
read docs/a2.bin ${TMP_DIR}/should_not_read.out
chmod 0400 docs/a2.bin
write ${ROOT_DIR}/README.md docs/a2.bin
chmod 0600 docs/a2.bin
create docs/delete.bin
write ${ROOT_DIR}/README.md docs/delete.bin
rm docs/delete.bin
ls docs
logout
exit
EOF
)"

  assert_contains "${ALICE_FLOW_LOG}" "Login successful."
  assert_contains "${ALICE_FLOW_LOG}" "/home/alice"
  assert_contains "${ALICE_FLOW_LOG}" "Created directory /home/alice/docs"
  assert_contains "${ALICE_FLOW_LOG}" "Created file /home/alice/docs/a.bin"
  assert_contains "${ALICE_FLOW_LOG}" "Wrote ${ROOT_DIR}/README.md -> /home/alice/docs/a.bin"
  assert_contains "${ALICE_FLOW_LOG}" "Read /home/alice/docs/a.bin -> ${ALICE_READ_OUT}"
  assert_contains "${ALICE_FLOW_LOG}" "Moved /home/alice/docs/a.bin -> /home/alice/docs/a2.bin"
  assert_contains "${ALICE_FLOW_LOG}" "a2.bin"
  assert_contains "${ALICE_FLOW_LOG}" "Created group devs"
  assert_contains "${ALICE_FLOW_LOG}" "Added bob to devs"
  assert_contains "${ALICE_FLOW_LOG}" "devs (owner)"
  assert_contains "${ALICE_FLOW_LOG}" "Created file /home/alice/docs/shared.bin"
  assert_contains "${ALICE_FLOW_LOG}" "Created file /home/alice/docs/delete.bin"
  assert_contains "${ALICE_FLOW_LOG}" "read failed: HTTP 403"
  assert_contains "${ALICE_FLOW_LOG}" "write failed: HTTP 403"
  assert_contains "${ALICE_FLOW_LOG}" "Deleted /home/alice/docs/delete.bin"

  cmp -s "${ROOT_DIR}/README.md" "${ALICE_READ_OUT}"

  set_req 2 "PASS" "challenge-based login works over the TLS client/server connection"
  set_req 3 "PASS" "create, write, read, rename, and delete all work from the CLI"
  set_req 4 "PASS" "home directories and nested directories are usable from the CLI"
}

run_bob_flow() {
  echo "[3/5] Running Bob CLI flow"
  run_client_flow "${BOB_FLOW_LOG}" $'login\nbob\nbobpass\npwd\ngroup-list\ngroup-key devs\nlogout\nexit\n'

  assert_contains "${BOB_FLOW_LOG}" "Login successful."
  assert_contains "${BOB_FLOW_LOG}" "/home/bob"
  assert_contains "${BOB_FLOW_LOG}" "devs"
  assert_contains "${BOB_FLOW_LOG}" "devs: "

  set_req 1 "PASS" "users and groups can be created and group membership can be managed through the CLI"
  set_req 5 "PARTIAL" "owner permissions are enforced and group membership works, but other-scope access and shared-path browsing are not fully exercised end to end"
}

verify_encryption_at_rest() {
  echo "[4/5] Verifying encryption at rest"
  local metadata_dump="${TMP_DIR}/metadata.txt"
  local storage_dump="${TMP_DIR}/storage.txt"
  local encrypted_path=""

  sqlite3 "${DB_PATH}" \
    "select cast(path as text), cast(name as text), object_type from file_metadatas order by id;" \
    >"${metadata_dump}"
  find "${STORAGE_ROOT}" -type f -o -type d | sort >"${storage_dump}"

  assert_not_contains "${metadata_dump}" "home"
  assert_not_contains "${metadata_dump}" "alice"
  assert_not_contains "${metadata_dump}" "bob"
  assert_not_contains "${metadata_dump}" "docs"
  assert_not_contains "${metadata_dump}" "shared.bin"

  encrypted_path="$(sqlite3 "${DB_PATH}" \
    "select cast(path as text) from file_metadatas where object_type = 'file' order by id desc limit 1;")"

  if [[ -z "${encrypted_path}" ]]; then
    echo "Failed to locate encrypted file path in metadata" >&2
    exit 1
  fi

  if cmp -s "${ROOT_DIR}/README.md" "${STORAGE_ROOT}${encrypted_path}"; then
    echo "Stored file matches plaintext unexpectedly" >&2
    exit 1
  fi

  set_req 6 "PASS" "metadata names and stored file contents are encrypted at rest"
}

verify_corruption_detection() {
  echo "[5/5] Verifying corruption detection"
  local -a encrypted_paths=()
  local content_path=""
  local name_path=""
  local before_hash=""
  local after_hash=""

  while IFS= read -r line; do
    encrypted_paths+=("${line}")
  done < <(
    sqlite3 "${DB_PATH}" \
      "select cast(path as text) from file_metadatas where object_type = 'file' order by id;"
  )

  if [[ "${#encrypted_paths[@]}" -lt 2 ]]; then
    echo "Need at least two files to verify name and content corruption detection" >&2
    exit 1
  fi

  name_path="${encrypted_paths[0]}"
  content_path="${encrypted_paths[${#encrypted_paths[@]}-1]}"

  before_hash="$(shasum -a 256 "${STORAGE_ROOT}${content_path}" | awk '{print $1}')"

  python3 - "${STORAGE_ROOT}${content_path}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
if not data:
    raise SystemExit("cannot corrupt empty file")
data[0] ^= 0x01
path.write_bytes(data)
PY

  after_hash="$(shasum -a 256 "${STORAGE_ROOT}${content_path}" | awk '{print $1}')"
  if [[ "${before_hash}" == "${after_hash}" ]]; then
    echo "Failed to corrupt stored ciphertext" >&2
    exit 1
  fi

  sqlite3 "${DB_PATH}" \
    "update file_metadatas set name = X'7a7a' where cast(path as text) = '${name_path}';"

  run_client_flow "${CORRUPT_FLOW_LOG}" $'login\nalice\nalicepass\nlogout\nexit\n'
  assert_contains "${CORRUPT_FLOW_LOG}" "Login successful."
  assert_contains "${CORRUPT_FLOW_LOG}" "Integrity warning:"
  assert_contains "${CORRUPT_FLOW_LOG}" "corrupted file(s)"
  assert_contains "${CORRUPT_FLOW_LOG}" "corrupted name(s)"

  set_req 7 "PASS" "the client detects corrupted names and contents immediately after login and warns the owner"
}

print_summary() {
  echo
  echo "Acceptance Test Summary"
  echo "Requirement 1: ${REQ1_STATUS} - ${REQ1_NOTE}"
  echo "Requirement 2: ${REQ2_STATUS} - ${REQ2_NOTE}"
  echo "Requirement 3: ${REQ3_STATUS} - ${REQ3_NOTE}"
  echo "Requirement 4: ${REQ4_STATUS} - ${REQ4_NOTE}"
  echo "Requirement 5: ${REQ5_STATUS} - ${REQ5_NOTE}"
  echo "Requirement 6: ${REQ6_STATUS} - ${REQ6_NOTE}"
  echo "Requirement 7: ${REQ7_STATUS} - ${REQ7_NOTE}"
  echo
  echo "Temp DB: ${DB_PATH}"
  echo "Temp storage: ${STORAGE_ROOT}"
  echo "Server log: ${SERVER_LOG}"
}

maybe_fail_for_unmet_requirements() {
  local unmet=0
  local partial=0
  local status=""

  for status in \
    "${REQ1_STATUS}" "${REQ2_STATUS}" "${REQ3_STATUS}" "${REQ4_STATUS}" \
    "${REQ5_STATUS}" "${REQ6_STATUS}" "${REQ7_STATUS}"; do
    if [[ "${status}" == "FAIL" ]]; then
      unmet=1
    fi
    if [[ "${status}" == "PARTIAL" ]]; then
      partial=1
    fi
  done

  if [[ "${STRICT}" == "1" ]]; then
    if [[ "${unmet}" -ne 0 || "${partial}" -ne 0 ]]; then
      exit 1
    fi
  fi
}

main() {
  require_file "${SCHEMA_PATH}"
  require_file "${CERT_PATH}"
  require_file "${KEY_PATH}"

  build_project
  start_server
  run_register_tests
  run_alice_flow
  run_bob_flow
  verify_encryption_at_rest
  verify_corruption_detection
  print_summary
  maybe_fail_for_unmet_requirements
}

main "$@"
