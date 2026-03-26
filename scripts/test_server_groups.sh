#!/usr/bin/env bash

set -euo pipefail

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
TOKEN="${TOKEN:-test-token-alice-123}"
GROUP_NAME="${GROUP_NAME:-shell-group-$$}"
TARGET_USER="${TARGET_USER:-bob}"
WRAPPED_GROUP_KEY="${WRAPPED_GROUP_KEY:-demo-wrapped-group-key}"
DB_PATH="${DB_PATH:-server/deploy/storage/sqlite_data/sfs.db}"

BASE_URL="https://${HOST}:${PORT}"
TMP_DIR="$(mktemp -d)"
LAST_BODY_FILE=""
LAST_STATUS=""

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

seed_users() {
  sqlite3 "$DB_PATH" <<'EOF'
INSERT OR IGNORE INTO users (id, username, public_encryption_key, public_signing_key)
VALUES
  (1, 'alice', X'01', X'02'),
  (2, 'bob', X'03', X'04');
EOF
}

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

echo "Testing group endpoints against ${HOST}:${PORT}"
echo "Using group: ${GROUP_NAME}"
echo "Target user: ${TARGET_USER}"

seed_users

create_group_json=$(printf '{"group_name":"%s"}' "$GROUP_NAME")
perform_request "create_group" "POST" "${BASE_URL}/groups" \
  "application/json" "$create_group_json"
assert_status "201"
assert_body_contains "\"group_name\":\"${GROUP_NAME}\""
echo "Create group OK"

add_member_json=$(
  printf '{"group_name":"%s","username":"%s","wrapped_group_key":"%s"}' \
    "$GROUP_NAME" "$TARGET_USER" "$WRAPPED_GROUP_KEY"
)
perform_request "add_member" "POST" "${BASE_URL}/groups/members" \
  "application/json" "$add_member_json"
assert_status "200"
assert_body_contains "user added to group"
echo "Add member OK"

perform_request "list_groups_after_add" "GET" \
  "${BASE_URL}/groups?username=${TARGET_USER}"
assert_status "200"
assert_body_contains "\"group_name\":\"${GROUP_NAME}\""
echo "List groups after add OK"

remove_member_json=$(
  printf '{"group_name":"%s","username":"%s"}' \
    "$GROUP_NAME" "$TARGET_USER"
)
perform_request "remove_member" "DELETE" "${BASE_URL}/groups/members" \
  "application/json" "$remove_member_json"
assert_status "200"
assert_body_contains "user removed from group"
echo "Remove member OK"

perform_request "list_groups_after_remove" "GET" \
  "${BASE_URL}/groups?username=${TARGET_USER}"
assert_status "200"
assert_body_not_contains "\"group_name\":\"${GROUP_NAME}\""
echo "List groups after remove OK"

echo "Server-side group create/add/list/remove test passed"
