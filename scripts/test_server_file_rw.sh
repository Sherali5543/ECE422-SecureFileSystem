#!/usr/bin/env bash

set -euo pipefail

HOST="${HOST:-localhost}"
PORT="${PORT:-8443}"
TOKEN="${TOKEN:-test-token-alice-123}"
FILEPATH="${FILEPATH:-/home/alice/docs/shell-test-$$.txt}"
WRITE_BODY="${WRITE_BODY:-hello from server read write test}"
OVERWRITE_BODY="${OVERWRITE_BODY:-updated contents from overwrite test}"

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

assert_body_equals() {
  local expected="$1"
  local actual

  actual="$(cat "$LAST_BODY_FILE")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Response body mismatch" >&2
    echo "Expected: $expected" >&2
    echo "Actual:   $actual" >&2
    exit 1
  fi
}

echo "Testing against ${HOST}:${PORT}"
echo "Using filepath: ${FILEPATH}"

create_json=$(printf '{"filepath":"%s"}' "$FILEPATH")
perform_request "create" "POST" "${BASE_URL}/files" "application/json" "$create_json"
assert_status "201"
echo "Create OK"

perform_request "write_one" "PUT" \
  "${BASE_URL}/files/content?filepath=${FILEPATH}" \
  "application/octet-stream" \
  "$WRITE_BODY"
assert_status "200"
echo "First write OK"

perform_request "read_one" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "200"
assert_body_equals "$WRITE_BODY"
echo "First read OK"

perform_request "write_two" "PUT" \
  "${BASE_URL}/files/content?filepath=${FILEPATH}" \
  "application/octet-stream" \
  "$OVERWRITE_BODY"
assert_status "200"
echo "Overwrite write OK"

perform_request "read_two" "GET" \
  "${BASE_URL}/files/contents?filepath=${FILEPATH}"
assert_status "200"
assert_body_equals "$OVERWRITE_BODY"
echo "Overwrite read OK"

echo "Server-side create/write/read test passed"
