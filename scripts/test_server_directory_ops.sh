#!/usr/bin/env bash

set -euo pipefail

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
TOKEN="${TOKEN:-test-token-alice-123}"
DB_PATH="${DB_PATH:-server/deploy/storage/sqlite_data/sfs.db}"
STORAGE_ROOT="${STORAGE_ROOT:-server/deploy/storage/sfs_storage}"
BASE_PARENT="${BASE_PARENT:-/home/alice/docs}"
TEST_SUFFIX="${TEST_SUFFIX:-$$}"
TEST_DIR="${TEST_DIR:-${BASE_PARENT}/mkdir-test-${TEST_SUFFIX}}"
RENAMED_DIR="${RENAMED_DIR:-${BASE_PARENT}/renamed-dir-${TEST_SUFFIX}}"
TEST_FILE="${TEST_FILE:-${TEST_DIR}/original.txt}"
MOVED_FILE="${MOVED_FILE:-${TEST_DIR}/moved.txt}"
MOVED_FILE_AFTER_DIR_MOVE="${MOVED_FILE_AFTER_DIR_MOVE:-${RENAMED_DIR}/moved.txt}"
WRITE_BODY="${WRITE_BODY:-directory move payload}"

BASE_URL="https://${HOST}:${PORT}"
TMP_DIR="$(mktemp -d)"
LAST_BODY_FILE=""
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

  if [[ -n "$content_type" ]]; then
    LAST_STATUS="$(
      curl -k -sS \
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

assert_body_not_contains() {
  local unexpected="$1"
  local actual

  actual="$(cat "$LAST_BODY_FILE")"
  if [[ "$actual" == *"$unexpected"* ]]; then
    echo "Did not expect response body to contain: $unexpected" >&2
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

echo "Testing directory endpoints against ${HOST}:${PORT}"
echo "Base parent: ${BASE_PARENT}"
echo "Test directory: ${TEST_DIR}"

seed_environment

mkdir_json=$(printf '{"dirpath":"%s"}' "$TEST_DIR")
perform_request "create_directory" "POST" "${BASE_URL}/directories" \
  "application/json" "$mkdir_json"
assert_status "201"
assert_body_contains "\"dirpath\":\"${TEST_DIR}\""
echo "Create directory OK"

perform_request "list_parent" "GET" "${BASE_URL}/files?filepath=${BASE_PARENT}"
assert_status "200"
assert_body_contains "\"directory\":\"${BASE_PARENT}\""
assert_body_contains "\"path\":\"${TEST_DIR}\""
assert_body_contains "\"object_type\":\"directory\""
echo "List parent directory OK"

create_file_json=$(printf '{"filepath":"%s"}' "$TEST_FILE")
perform_request "create_file" "POST" "${BASE_URL}/files" \
  "application/json" "$create_file_json"
assert_status "201"
assert_body_contains "\"filepath\":\"${TEST_FILE}\""
echo "Create file for move OK"

perform_request "write_file" "PUT" \
  "${BASE_URL}/files/content?filepath=${TEST_FILE}" \
  "application/octet-stream" "$WRITE_BODY"
assert_status "200"
assert_body_contains "file written"
echo "Write file OK"

move_file_json=$(
  printf '{"source_filepath":"%s","destination_filepath":"%s"}' \
    "$TEST_FILE" "$MOVED_FILE"
)
perform_request "move_file" "POST" "${BASE_URL}/files/move" \
  "application/json" "$move_file_json"
assert_status "200"
assert_body_contains "\"from\":\"${TEST_FILE}\""
assert_body_contains "\"to\":\"${MOVED_FILE}\""
echo "Move file OK"

perform_request "read_moved_file" "GET" \
  "${BASE_URL}/files/contents?filepath=${MOVED_FILE}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
echo "Read moved file OK"

permissions_json=$(printf '{"filepath":"%s","mode_bits":"0600"}' "$MOVED_FILE")
perform_request "patch_permissions" "PATCH" \
  "${BASE_URL}/files/permissions" \
  "application/json" "$permissions_json"
assert_status "200"
assert_body_contains "\"filepath\":\"${MOVED_FILE}\""
assert_body_contains "\"mode_bits\":384"
echo "Update permissions OK"

perform_request "list_test_dir" "GET" "${BASE_URL}/files?filepath=${TEST_DIR}"
assert_status "200"
assert_body_contains "\"path\":\"${MOVED_FILE}\""
assert_body_contains "\"mode_bits\":384"
echo "List moved file in directory OK"

move_directory_json=$(
  printf '{"source_filepath":"%s","destination_filepath":"%s"}' \
    "$TEST_DIR" "$RENAMED_DIR"
)
perform_request "move_directory" "POST" "${BASE_URL}/files/move" \
  "application/json" "$move_directory_json"
assert_status "200"
assert_body_contains "\"from\":\"${TEST_DIR}\""
assert_body_contains "\"to\":\"${RENAMED_DIR}\""
echo "Move directory OK"

perform_request "list_parent_after_move" "GET" \
  "${BASE_URL}/files?filepath=${BASE_PARENT}"
assert_status "200"
assert_body_contains "\"path\":\"${RENAMED_DIR}\""
assert_body_not_contains "\"path\":\"${TEST_DIR}\""
echo "List parent after directory move OK"

perform_request "read_after_directory_move" "GET" \
  "${BASE_URL}/files/contents?filepath=${MOVED_FILE_AFTER_DIR_MOVE}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
echo "Read file after directory move OK"

echo "Server-side mkdir/list/move/permissions test passed"
