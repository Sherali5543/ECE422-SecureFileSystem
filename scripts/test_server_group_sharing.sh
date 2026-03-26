#!/usr/bin/env bash

set -euo pipefail

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
TOKEN="${TOKEN:-test-token-alice-123}"
DB_PATH="${DB_PATH:-server/deploy/storage/sqlite_data/sfs.db}"
STORAGE_ROOT="${STORAGE_ROOT:-server/deploy/storage/sfs_storage}"
BASE_PARENT="${BASE_PARENT:-/home/alice/docs}"
TEST_SUFFIX="${TEST_SUFFIX:-$$}"
GROUP_NAME="${GROUP_NAME:-devs-${TEST_SUFFIX}}"
FILEPATH="${FILEPATH:-${BASE_PARENT}/group-file-${TEST_SUFFIX}.bin}"
OWNER_WRAPPED_GROUP_KEY="${OWNER_WRAPPED_GROUP_KEY:-a1b2c3d4}"
BOB_WRAPPED_GROUP_KEY="${BOB_WRAPPED_GROUP_KEY:-b2c3d4e5}"
WRAPPED_FEK_OWNER="${WRAPPED_FEK_OWNER:-0a0b0c0d}"
WRAPPED_FEK_GROUP="${WRAPPED_FEK_GROUP:-deadbeef}"
WRAPPED_FEK_OTHER="${WRAPPED_FEK_OTHER:-}"
WRITE_BODY="${WRITE_BODY:-group-shared-encrypted-payload}"

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

assert_header_contains() {
  local expected="$1"

  if ! grep -qi "$expected" "$LAST_HEADER_FILE"; then
    echo "Expected response headers to contain: $expected" >&2
    echo "Actual headers:" >&2
    cat "$LAST_HEADER_FILE" >&2
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

sql_quote() {
  printf "%s" "$1" | sed "s/'/''/g"
}

seed_environment() {
  mkdir -p "${STORAGE_ROOT}/home/alice/docs"

  sqlite3 "$DB_PATH" <<'EOF'
INSERT OR IGNORE INTO users (id, username, public_encryption_key, public_signing_key)
VALUES
  (1, 'alice', X'01', X'02'),
  (2, 'bob', X'03', X'04');

INSERT OR IGNORE INTO file_metadatas
(path, name, owner_id, group_id, mode_bits, object_type, created_at, updated_at)
VALUES
  (CAST('/home' AS BLOB), CAST('home' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now')),
  (CAST('/home/alice' AS BLOB), CAST('alice' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now')),
  (CAST('/home/alice/docs' AS BLOB), CAST('docs' AS BLOB), 1, NULL, 493, 'directory', strftime('%s','now'), strftime('%s','now'));
EOF
}

echo "Testing group-sharing flow against ${HOST}:${PORT}"
echo "Using group: ${GROUP_NAME}"
echo "Using filepath: ${FILEPATH}"

seed_environment

group_json=$(
  printf '{"group_name":"%s","wrapped_group_key":"%s"}' \
    "$GROUP_NAME" "$OWNER_WRAPPED_GROUP_KEY"
)
perform_request "create_group" "POST" "${BASE_URL}/groups" \
  "application/json" "$group_json"
assert_status "201"
assert_body_contains "\"group_name\":\"${GROUP_NAME}\""
assert_body_contains "\"owner_id\":1"
echo "Create group OK"

perform_request "get_group_key_owner" "GET" \
  "${BASE_URL}/groups/key?group_name=${GROUP_NAME}"
assert_status "200"
assert_body_contains "\"group_name\":\"${GROUP_NAME}\""
assert_body_contains "\"owner_id\":1"
assert_body_contains "\"wrapped_group_key\":\"${OWNER_WRAPPED_GROUP_KEY}\""
echo "Fetch owner wrapped group key OK"

member_json=$(
  printf '{"group_name":"%s","username":"bob","wrapped_group_key":"%s"}' \
    "$GROUP_NAME" "$BOB_WRAPPED_GROUP_KEY"
)
perform_request "add_member" "POST" "${BASE_URL}/groups/members" \
  "application/json" "$member_json"
assert_status "200"
assert_body_contains "user added to group"
echo "Add bob to group OK"

perform_request "list_bob_groups" "GET" \
  "${BASE_URL}/groups?username=bob"
assert_status "200"
assert_body_contains "\"username\":\"bob\""
assert_body_contains "\"group_name\":\"${GROUP_NAME}\""
assert_body_contains "\"owner_id\":1"
assert_body_contains "\"is_owner\":false"
echo "List bob groups OK"

create_file_json=$(
  printf '{"filepath":"%s","group_name":"%s","wrapped_fek_owner":"%s","wrapped_fek_group":"%s"}' \
    "$FILEPATH" "$GROUP_NAME" "$WRAPPED_FEK_OWNER" "$WRAPPED_FEK_GROUP"
)
perform_request "create_group_file" "POST" "${BASE_URL}/files" \
  "application/json" "$create_file_json"
assert_status "201"
assert_body_contains "\"filepath\":\"${FILEPATH}\""
echo "Create file bound to group OK"

group_name_sql="$(sql_quote "$GROUP_NAME")"
filepath_sql="$(sql_quote "$FILEPATH")"

assert_sql_equals \
  "SELECT group_id FROM file_metadatas WHERE CAST(path AS TEXT) = '${filepath_sql}';" \
  "$(sqlite3 "$DB_PATH" "SELECT id FROM groups WHERE name = '${group_name_sql}';")"
assert_sql_equals \
  "SELECT hex(wrapped_fek_group) FROM file_metadatas WHERE CAST(path AS TEXT) = '${filepath_sql}';" \
  "$(uppercase_hex "$WRAPPED_FEK_GROUP")"
echo "File metadata stored group_id and wrapped_fek_group OK"

perform_request "write_group_file" "PUT" \
  "${BASE_URL}/files/content?filepath=${FILEPATH}" \
  "application/octet-stream" "$WRITE_BODY"
assert_status "200"
assert_body_contains "file written"
echo "Write grouped file OK"

perform_request "read_group_file" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
assert_header_contains "X-Wrapped-FEK: ${WRAPPED_FEK_OWNER}"
assert_header_contains "X-FEK-Scope: owner"
echo "Read grouped file as owner OK"

remove_member_json=$(
  printf '{"group_name":"%s","username":"bob"}' "$GROUP_NAME"
)
perform_request "remove_member" "DELETE" "${BASE_URL}/groups/members" \
  "application/json" "$remove_member_json"
assert_status "200"
assert_body_contains "user removed from group"
echo "Remove bob from group OK"

perform_request "list_bob_groups_after_remove" "GET" \
  "${BASE_URL}/groups?username=bob"
assert_status "200"
assert_body_contains "\"username\":\"bob\""
assert_body_not_contains "\"group_name\":\"${GROUP_NAME}\""
echo "Verify bob removal from group OK"

echo "Server-side group ownership, key retrieval, membership, and grouped file-create test passed"
