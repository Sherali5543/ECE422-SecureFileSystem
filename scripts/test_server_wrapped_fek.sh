#!/usr/bin/env bash

set -euo pipefail

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
TOKEN="${TOKEN:-test-token-alice-123}"
DB_PATH="${DB_PATH:-server/deploy/storage/sqlite_data/sfs.db}"
STORAGE_ROOT="${STORAGE_ROOT:-server/deploy/storage/sfs_storage}"
BASE_PARENT="${BASE_PARENT:-/home/alice/docs}"
TEST_SUFFIX="${TEST_SUFFIX:-$$}"
FILEPATH="${FILEPATH:-${BASE_PARENT}/fek-test-${TEST_SUFFIX}.bin}"
WRITE_BODY="${WRITE_BODY:-encrypted-payload-demo}"
WRAPPED_FEK_OWNER="${WRAPPED_FEK_OWNER:-a1b2c3d4}"
WRAPPED_FEK_GROUP="${WRAPPED_FEK_GROUP:-deadbeef}"
WRAPPED_FEK_OTHER="${WRAPPED_FEK_OTHER:-00112233}"
UPDATED_WRAPPED_FEK_OWNER="${UPDATED_WRAPPED_FEK_OWNER:-cafebabe}"
UPDATED_WRAPPED_FEK_GROUP="${UPDATED_WRAPPED_FEK_GROUP:-}"
UPDATED_WRAPPED_FEK_OTHER="${UPDATED_WRAPPED_FEK_OTHER:-}"

BASE_URL="https://${HOST}:${PORT}"
TMP_DIR="$(mktemp -d)"
LAST_BODY_FILE=""
LAST_HEADER_FILE=""
LAST_STATUS=""

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

perform_request() {
  local name="$1"
  local method="$2"
  local url="$3"
  local content_type="${4:-}"
  local body="${5:-}"

  LAST_BODY_FILE="${TMP_DIR}/${name}.body"
  LAST_HEADER_FILE="${TMP_DIR}/${name}.headers"

  if [[ -n "$content_type" ]]; then
    LAST_STATUS="$(
      curl -k -sS \
        -D "$LAST_HEADER_FILE" \
        -o "$LAST_BODY_FILE" \
        -w '%{http_code}' \
        -X "$method" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Connection: close" \
        -H "Content-Type: ${content_type}" \
        --data-binary "$body" \
        "$url"
    )"
  else
    LAST_STATUS="$(
      curl -k -sS \
        -D "$LAST_HEADER_FILE" \
        -o "$LAST_BODY_FILE" \
        -w '%{http_code}' \
        -X "$method" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Connection: close" \
        "$url"
    )"
  fi
}

assert_status() {
  local expected="$1"

  if [[ "$LAST_STATUS" != "$expected" ]]; then
    echo "Expected HTTP ${expected} but got ${LAST_STATUS}" >&2
    if [[ -f "$LAST_BODY_FILE" ]]; then
      echo "Response body:" >&2
      cat "$LAST_BODY_FILE" >&2
      echo >&2
    fi
    exit 1
  fi
}

assert_body_contains() {
  local expected="$1"
  local actual

  actual="$(cat "$LAST_BODY_FILE")"
  if [[ "$actual" != *"$expected"* ]]; then
    echo "Expected response body to contain: $expected" >&2
    echo "Actual: $actual" >&2
    exit 1
  fi
}

assert_body_equals() {
  local expected="$1"
  local actual

  actual="$(cat "$LAST_BODY_FILE")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected exact response body: $expected" >&2
    echo "Actual: $actual" >&2
    exit 1
  fi
}

assert_header_contains() {
  local expected="$1"

  if ! grep -qi "$expected" "$LAST_HEADER_FILE"; then
    echo "Expected response headers to contain: $expected" >&2
    echo "Actual headers:" >&2
    cat "$LAST_HEADER_FILE" >&2
    exit 1
  fi
}

assert_sql_equals() {
  local sql="$1"
  local expected="$2"
  local actual

  actual="$(sqlite3 "$DB_PATH" "$sql")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected SQL result: $expected" >&2
    echo "Actual SQL result: $actual" >&2
    echo "SQL: $sql" >&2
    exit 1
  fi
}

uppercase_hex() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

seed_environment() {
  mkdir -p "${STORAGE_ROOT}/home/alice/docs"

  sqlite3 "$DB_PATH" <<'EOF'
INSERT OR IGNORE INTO users (id, username, public_encryption_key, public_signing_key)
VALUES (1, 'alice', X'01', X'02');

INSERT OR IGNORE INTO file_metadatas
(path, name, owner_id, group_id, mode_bits, object_type, created_at, updated_at)
VALUES
  (CAST('/home' AS BLOB), CAST('home' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now')),
  (CAST('/home/alice' AS BLOB), CAST('alice' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now')),
  (CAST('/home/alice/docs' AS BLOB), CAST('docs' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now'));
EOF
}

echo "Testing wrapped FEK file flow against ${HOST}:${PORT}"
echo "Using filepath: ${FILEPATH}"

seed_environment

create_json=$(
  printf '{"filepath":"%s","wrapped_fek_owner":"%s","wrapped_fek_group":"%s","wrapped_fek_other":"%s"}' \
    "$FILEPATH" "$WRAPPED_FEK_OWNER" "$WRAPPED_FEK_GROUP" "$WRAPPED_FEK_OTHER"
)
perform_request "create_file" "POST" "${BASE_URL}/files" \
  "application/json" "$create_json"
assert_status "201"
assert_body_contains "\"filepath\":\"${FILEPATH}\""
echo "Create file with wrapped FEKs OK"

perform_request "write_file" "PUT" \
  "${BASE_URL}/files/content?filepath=${FILEPATH}" \
  "application/octet-stream" "$WRITE_BODY"
assert_status "200"
assert_body_contains "file written"
echo "Write file OK"

perform_request "read_file" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
assert_header_contains "X-Wrapped-FEK: ${WRAPPED_FEK_OWNER}"
assert_header_contains "X-FEK-Scope: owner"
echo "Read file returned wrapped FEK and owner scope OK"

permissions_json=$(
  printf '{"filepath":"%s","mode_bits":"0600","wrapped_fek_owner":"%s"}' \
    "$FILEPATH" "$UPDATED_WRAPPED_FEK_OWNER"
)
perform_request "patch_permissions" "PATCH" \
  "${BASE_URL}/files/permissions" \
  "application/json" "$permissions_json"
assert_status "200"
assert_body_contains "\"filepath\":\"${FILEPATH}\""
assert_body_contains "\"mode_bits\":384"
echo "Update permissions and owner FEK OK"

assert_sql_equals \
  "SELECT hex(wrapped_fek_owner) FROM file_metadatas WHERE CAST(path AS TEXT) = '${FILEPATH}';" \
  "$(uppercase_hex "$UPDATED_WRAPPED_FEK_OWNER")"
assert_sql_equals \
  "SELECT COUNT(*) FROM file_metadatas WHERE CAST(path AS TEXT) = '${FILEPATH}' AND wrapped_fek_group IS NULL;" \
  "1"
assert_sql_equals \
  "SELECT COUNT(*) FROM file_metadatas WHERE CAST(path AS TEXT) = '${FILEPATH}' AND wrapped_fek_other IS NULL;" \
  "1"
echo "Database FEK state after permission update OK"

perform_request "read_file_after_patch" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
assert_header_contains "X-Wrapped-FEK: ${UPDATED_WRAPPED_FEK_OWNER}"
assert_header_contains "X-FEK-Scope: owner"
echo "Read file returned updated owner FEK after permission patch OK"

owner_write_only_json=$(
  printf '{"filepath":"%s","mode_bits":"0200","wrapped_fek_owner":"%s"}' \
    "$FILEPATH" "$UPDATED_WRAPPED_FEK_OWNER"
)
perform_request "patch_owner_write_only" "PATCH" \
  "${BASE_URL}/files/permissions" \
  "application/json" "$owner_write_only_json"
assert_status "200"
assert_body_contains "\"mode_bits\":128"
echo "Update permissions to owner-write-only OK"

perform_request "read_denied" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "403"
assert_body_contains "insufficient permissions"
echo "Read denied after removing owner read permission OK"

owner_read_only_json=$(
  printf '{"filepath":"%s","mode_bits":"0400","wrapped_fek_owner":"%s"}' \
    "$FILEPATH" "$UPDATED_WRAPPED_FEK_OWNER"
)
perform_request "patch_owner_read_only" "PATCH" \
  "${BASE_URL}/files/permissions" \
  "application/json" "$owner_read_only_json"
assert_status "200"
assert_body_contains "\"mode_bits\":256"
echo "Update permissions to owner-read-only OK"

perform_request "write_denied" "PUT" \
  "${BASE_URL}/files/content?filepath=${FILEPATH}" \
  "application/octet-stream" "should-not-write"
assert_status "403"
assert_body_contains "insufficient permissions"
echo "Write denied after removing owner write permission OK"

echo "Server-side wrapped FEK create/read/permissions enforcement test passed"
