#!/usr/bin/env bash

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SRC="$REPO_ROOT/tests/db_wrapper_test.c"
DB_SRC="$REPO_ROOT/server/src/db/db.c"
SCHEMA_HELPER_SRC="$REPO_ROOT/server/src/db/schema_helper.c"
INCLUDE_DIR="$REPO_ROOT/server/include"
SCHEMA_PATH="$REPO_ROOT/server/db/init/001-schema.sql"
TMP_ROOT="${TMPDIR:-/tmp}"
TMP_DIR="$(mktemp -d "$TMP_ROOT/sfs-db-wrapper-test.XXXXXX")"
TEST_BIN="$TMP_DIR/db_wrapper_test"
DB_PATH="$TMP_DIR/test.db"

cleanup() {
  if [ "${KEEP_DB:-0}" = "1" ]; then
    printf 'Keeping wrapper test artifacts in %s\n' "$TMP_DIR"
    return
  fi

  rm -rf "$TMP_DIR"
}

trap cleanup EXIT

printf 'Compiling DB wrapper test harness...\n'
cc -std=c11 -Wall -Wextra -Wpedantic \
  -I"$INCLUDE_DIR" \
  "$TEST_SRC" \
  "$DB_SRC" \
  "$SCHEMA_HELPER_SRC" \
  -lsqlite3 \
  -o "$TEST_BIN"

printf 'Running DB wrapper tests against %s\n' "$DB_PATH"
"$TEST_BIN" "$DB_PATH" "$SCHEMA_PATH"
