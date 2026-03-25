#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"

static int failures = 0;
static int checks = 0;

static int alice_id = 0;
static int bob_id = 0;
static int admins_id = 0;
static int staff_id = 0;

static void expect_true(int condition, const char* label) {
  checks++;
  if (condition) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s\n", label);
}

static void expect_int_eq(int actual, int expected, const char* label) {
  checks++;
  if (actual == expected) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s (expected %d, got %d)\n", label, expected, actual);
}

static void expect_size_eq(size_t actual, size_t expected, const char* label) {
  checks++;
  if (actual == expected) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s (expected %zu, got %zu)\n", label, expected, actual);
}

static void expect_ll_eq(long long actual, long long expected,
                         const char* label) {
  checks++;
  if (actual == expected) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s (expected %lld, got %lld)\n", label, expected, actual);
}

static void expect_string_eq(const char* actual, const char* expected,
                             const char* label) {
  checks++;
  if (actual != NULL && strcmp(actual, expected) == 0) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s (expected '%s', got '%s')\n", label, expected,
         actual == NULL ? "(null)" : actual);
}

static void expect_blob_eq(const unsigned char* actual,
                           const unsigned char* expected, size_t len,
                           const char* label) {
  checks++;
  if (len == 0 || memcmp(actual, expected, len) == 0) {
    printf("PASS: %s\n", label);
    return;
  }

  failures++;
  printf("FAIL: %s (blob mismatch)\n", label);
}

static void set_blob(unsigned char* dest, size_t* dest_len, const void* src,
                     size_t src_len) {
  if (src_len > 0) {
    memcpy(dest, src, src_len);
  }
  *dest_len = src_len;
}

static void init_file_metadata(db_file_metadata_t* metadata, const char* path,
                               const char* name, int owner_id,
                               int has_group_id, int group_id, int mode_bits,
                               const char* object_type, long long created_at,
                               long long updated_at) {
  memset(metadata, 0, sizeof(*metadata));
  set_blob(metadata->path, &metadata->path_len, path, strlen(path));
  set_blob(metadata->name, &metadata->name_len, name, strlen(name));
  metadata->owner_id = owner_id;
  metadata->has_group_id = has_group_id;
  metadata->group_id = group_id;
  metadata->mode_bits = mode_bits;
  strncpy(metadata->object_type, object_type, sizeof(metadata->object_type) - 1);
  metadata->created_at = created_at;
  metadata->updated_at = updated_at;
}

static void test_invalid_init_inputs(const char* schema_path) {
  server_context_t ctx;

  memset(&ctx, 0, sizeof(ctx));
  expect_int_eq(db_init(NULL), -1, "db_init rejects null context");
  expect_true(db_handle(NULL) == NULL,
              "db_handle returns NULL for null context");

  ctx.schema_path = schema_path;
  expect_int_eq(db_init(&ctx), -1, "db_init rejects missing db path");

  memset(&ctx, 0, sizeof(ctx));
  ctx.db_path = "/tmp/unused-test.db";
  expect_int_eq(db_init(&ctx), -1, "db_init rejects missing schema path");

  db_cleanup(NULL);
  expect_true(1, "db_cleanup tolerates null context");
}

static void test_user_wrappers(server_context_t* ctx) {
  static const unsigned char alice_encryption_key[] = {0x01, 0x02, 0x03, 0x04};
  static const unsigned char alice_signing_key[] = {0x11, 0x12, 0x13};
  static const unsigned char bob_encryption_key[] = {0xAA};
  static const unsigned char bob_signing_key[] = {0xBB, 0xBC};
  db_user_t user;

  memset(&user, 0, sizeof(user));
  expect_int_eq(db_find_user_by_username(NULL, "alice", &user), -1,
                "db_find_user_by_username rejects null context");
  expect_int_eq(db_find_user_by_username(ctx, NULL, &user), -1,
                "db_find_user_by_username rejects null username");
  expect_int_eq(db_find_user_by_username(ctx, "alice", NULL), -1,
                "db_find_user_by_username rejects null output");
  expect_int_eq(db_find_user_by_id(NULL, 1, &user), -1,
                "db_find_user_by_id rejects null context");
  expect_int_eq(db_find_user_by_id(ctx, 1, NULL), -1,
                "db_find_user_by_id rejects null output");

  expect_int_eq(db_create_user(NULL, "alice", alice_encryption_key,
                               sizeof(alice_encryption_key),
                               alice_signing_key, sizeof(alice_signing_key),
                               &alice_id),
                -1, "db_create_user rejects null context");
  expect_int_eq(db_create_user(ctx, NULL, alice_encryption_key,
                               sizeof(alice_encryption_key),
                               alice_signing_key, sizeof(alice_signing_key),
                               &alice_id),
                -1, "db_create_user rejects null username");
  expect_int_eq(db_create_user(ctx, "alice", NULL,
                               sizeof(alice_encryption_key),
                               alice_signing_key, sizeof(alice_signing_key),
                               &alice_id),
                -1, "db_create_user rejects null encryption key pointer");
  expect_int_eq(db_create_user(ctx, "alice", alice_encryption_key,
                               sizeof(alice_encryption_key), NULL,
                               sizeof(alice_signing_key), &alice_id),
                -1, "db_create_user rejects null signing key pointer");

  expect_int_eq(db_find_user_by_username(ctx, "alice", &user), 0,
                "db_find_user_by_username returns not found before insert");
  expect_int_eq(db_find_user_by_id(ctx, 9999, &user), 0,
                "db_find_user_by_id returns not found for unknown id");

  alice_id = 0;
  expect_int_eq(db_create_user(ctx, "alice", alice_encryption_key,
                               sizeof(alice_encryption_key),
                               alice_signing_key, sizeof(alice_signing_key),
                               &alice_id),
                0, "db_create_user inserts alice");
  expect_true(alice_id > 0, "db_create_user returns a user id");

  memset(&user, 0, sizeof(user));
  expect_int_eq(db_find_user_by_username(ctx, "alice", &user), 1,
                "db_find_user_by_username returns found for alice");
  expect_int_eq(user.id, alice_id, "db_find_user_by_username returns alice id");
  expect_string_eq(user.username, "alice",
                   "db_find_user_by_username returns alice username");
  expect_size_eq(user.public_encryption_key_len,
                 sizeof(alice_encryption_key),
                 "db_find_user_by_username returns alice encryption key length");
  expect_blob_eq(user.public_encryption_key, alice_encryption_key,
                 sizeof(alice_encryption_key),
                 "db_find_user_by_username returns alice encryption key bytes");
  expect_size_eq(user.public_signing_key_len, sizeof(alice_signing_key),
                 "db_find_user_by_username returns alice signing key length");
  expect_blob_eq(user.public_signing_key, alice_signing_key,
                 sizeof(alice_signing_key),
                 "db_find_user_by_username returns alice signing key bytes");

  memset(&user, 0, sizeof(user));
  expect_int_eq(db_find_user_by_id(ctx, alice_id, &user), 1,
                "db_find_user_by_id returns stored alice row");
  expect_string_eq(user.username, "alice",
                   "db_find_user_by_id returns alice username");

  expect_int_eq(db_create_user(ctx, "alice", alice_encryption_key,
                               sizeof(alice_encryption_key),
                               alice_signing_key, sizeof(alice_signing_key),
                               &alice_id),
                -1, "db_create_user rejects duplicate usernames");

  bob_id = 0;
  expect_int_eq(db_create_user(ctx, "bob", bob_encryption_key, 0,
                               bob_signing_key, sizeof(bob_signing_key),
                               &bob_id),
                0, "db_create_user inserts bob with zero-length encryption key");
  expect_true(bob_id > 0, "db_create_user returns a user id for bob");

  memset(&user, 0, sizeof(user));
  expect_int_eq(db_find_user_by_username(ctx, "bob", &user), 1,
                "db_find_user_by_username returns found for bob");
  expect_size_eq(user.public_encryption_key_len, 0,
                 "db_find_user_by_username returns zero-length encryption key for bob");
  expect_size_eq(user.public_signing_key_len, sizeof(bob_signing_key),
                 "db_find_user_by_username returns signing key length for bob");
  expect_blob_eq(user.public_signing_key, bob_signing_key,
                 sizeof(bob_signing_key),
                 "db_find_user_by_username returns signing key bytes for bob");
}

static void test_group_wrappers(server_context_t* ctx) {
  db_group_t group;

  memset(&group, 0, sizeof(group));
  expect_int_eq(db_find_group_by_name(NULL, "admins", &group), -1,
                "db_find_group_by_name rejects null context");
  expect_int_eq(db_find_group_by_name(ctx, NULL, &group), -1,
                "db_find_group_by_name rejects null group name");
  expect_int_eq(db_find_group_by_name(ctx, "admins", NULL), -1,
                "db_find_group_by_name rejects null output");
  expect_int_eq(db_find_group_by_id(NULL, 1, &group), -1,
                "db_find_group_by_id rejects null context");
  expect_int_eq(db_find_group_by_id(ctx, 1, NULL), -1,
                "db_find_group_by_id rejects null output");

  expect_int_eq(db_create_group(NULL, "admins", &admins_id), -1,
                "db_create_group rejects null context");
  expect_int_eq(db_create_group(ctx, NULL, &admins_id), -1,
                "db_create_group rejects null group name");

  expect_int_eq(db_find_group_by_name(ctx, "admins", &group), 0,
                "db_find_group_by_name returns not found before insert");
  expect_int_eq(db_find_group_by_id(ctx, 9999, &group), 0,
                "db_find_group_by_id returns not found for unknown id");

  admins_id = 0;
  expect_int_eq(db_create_group(ctx, "admins", &admins_id), 0,
                "db_create_group inserts admins");
  expect_true(admins_id > 0, "db_create_group returns a group id");

  memset(&group, 0, sizeof(group));
  expect_int_eq(db_find_group_by_name(ctx, "admins", &group), 1,
                "db_find_group_by_name returns found for admins");
  expect_int_eq(group.id, admins_id,
                "db_find_group_by_name returns admins id");
  expect_string_eq(group.name, "admins",
                   "db_find_group_by_name returns admins name");

  memset(&group, 0, sizeof(group));
  expect_int_eq(db_find_group_by_id(ctx, admins_id, &group), 1,
                "db_find_group_by_id returns stored admins row");
  expect_string_eq(group.name, "admins",
                   "db_find_group_by_id returns admins name");

  expect_int_eq(db_create_group(ctx, "admins", &admins_id), -1,
                "db_create_group rejects duplicate group names");

  staff_id = 0;
  expect_int_eq(db_create_group(ctx, "staff", &staff_id), 0,
                "db_create_group inserts staff");
  expect_true(staff_id > 0, "db_create_group returns a group id for staff");
}

static void test_group_membership_wrappers(server_context_t* ctx) {
  static const unsigned char admins_key[] = {0xA1, 0xB2};
  static const unsigned char staff_key[] = {0xC3, 0xD4, 0xE5};
  static const unsigned char bob_staff_key[] = {0xF6};
  int is_member = -1;
  size_t membership_count = 0;
  db_group_membership_t memberships[4];

  memset(memberships, 0, sizeof(memberships));
  expect_int_eq(db_add_user_to_group(NULL, alice_id, admins_id, admins_key,
                                     sizeof(admins_key)),
                -1, "db_add_user_to_group rejects null context");
  expect_int_eq(db_add_user_to_group(ctx, alice_id, admins_id, NULL,
                                     sizeof(admins_key)),
                -1, "db_add_user_to_group rejects null wrapped key");

  expect_int_eq(db_is_user_in_group(NULL, alice_id, admins_id, &is_member), -1,
                "db_is_user_in_group rejects null context");
  expect_int_eq(db_is_user_in_group(ctx, alice_id, admins_id, NULL), -1,
                "db_is_user_in_group rejects null output");

  is_member = -1;
  expect_int_eq(db_is_user_in_group(ctx, alice_id, admins_id, &is_member), 0,
                "db_is_user_in_group returns success before membership exists");
  expect_int_eq(is_member, 0,
                "db_is_user_in_group returns false before membership exists");

  expect_int_eq(db_get_user_groups(NULL, alice_id, memberships, 4,
                                   &membership_count),
                -1, "db_get_user_groups rejects null context");
  expect_int_eq(db_get_user_groups(ctx, alice_id, NULL, 1, &membership_count),
                -1, "db_get_user_groups rejects null output buffer");

  expect_int_eq(db_add_user_to_group(ctx, alice_id, admins_id, admins_key,
                                     sizeof(admins_key)),
                0, "db_add_user_to_group inserts alice into admins");
  expect_int_eq(db_add_user_to_group(ctx, alice_id, staff_id, staff_key,
                                     sizeof(staff_key)),
                0, "db_add_user_to_group inserts alice into staff");
  expect_int_eq(db_add_user_to_group(ctx, bob_id, staff_id, bob_staff_key,
                                     sizeof(bob_staff_key)),
                0, "db_add_user_to_group inserts bob into staff");

  expect_int_eq(db_add_user_to_group(ctx, alice_id, admins_id, admins_key,
                                     sizeof(admins_key)),
                -1, "db_add_user_to_group rejects duplicate memberships");
  expect_int_eq(db_add_user_to_group(ctx, 9999, admins_id, admins_key,
                                     sizeof(admins_key)),
                -1, "db_add_user_to_group rejects invalid user ids");
  expect_int_eq(db_add_user_to_group(ctx, alice_id, 9999, admins_key,
                                     sizeof(admins_key)),
                -1, "db_add_user_to_group rejects invalid group ids");

  is_member = 0;
  expect_int_eq(db_is_user_in_group(ctx, alice_id, admins_id, &is_member), 0,
                "db_is_user_in_group returns success after membership insert");
  expect_int_eq(is_member, 1,
                "db_is_user_in_group returns true after membership insert");

  membership_count = 0;
  memset(memberships, 0, sizeof(memberships));
  expect_int_eq(db_get_user_groups(ctx, alice_id, memberships, 4,
                                   &membership_count),
                0, "db_get_user_groups returns alice memberships");
  expect_size_eq(membership_count, 2,
                 "db_get_user_groups returns two memberships for alice");
  expect_string_eq(memberships[0].group.name, "admins",
                   "db_get_user_groups orders memberships by group name");
  expect_int_eq(memberships[0].group_id, admins_id,
                "db_get_user_groups returns admins id");
  expect_blob_eq(memberships[0].wrapped_group_key, admins_key,
                 sizeof(admins_key),
                 "db_get_user_groups returns admins wrapped key");
  expect_string_eq(memberships[1].group.name, "staff",
                   "db_get_user_groups returns staff membership");
  expect_int_eq(memberships[1].group_id, staff_id,
                "db_get_user_groups returns staff id");
  expect_blob_eq(memberships[1].wrapped_group_key, staff_key,
                 sizeof(staff_key),
                 "db_get_user_groups returns staff wrapped key");

  membership_count = 0;
  expect_int_eq(db_get_user_groups(ctx, alice_id, NULL, 0, &membership_count),
                0, "db_get_user_groups supports count-only queries");
  expect_size_eq(membership_count, 2,
                 "db_get_user_groups count-only query returns two groups");
}

static void test_file_metadata_wrappers(server_context_t* ctx) {
  static const unsigned char owner_fek[] = {0x11, 0x12};
  static const unsigned char group_fek[] = {0x21, 0x22};
  static const unsigned char other_fek[] = {0x31};
  static const unsigned char updated_owner_fek[] = {0x41, 0x42, 0x43};
  static const unsigned char updated_group_fek[] = {0x51};
  static const unsigned char updated_other_fek[] = {0x61, 0x62};
  static const char docs_path[] = "/docs";
  static const char archive_path[] = "/docs/archive";
  static const char report_path[] = "/docs/report.txt";
  static const char notes_path[] = "/docs/notes.txt";
  static const char readme_path[] = "/readme.md";
  static const char old_path[] = "/docs/archive/old.txt";
  db_file_metadata_t metadata;
  db_file_metadata_t entries[4];
  size_t count = 0;
  int metadata_id = 0;

  memset(&metadata, 0, sizeof(metadata));
  expect_int_eq(db_create_file_metadata(NULL, &metadata, &metadata_id), -1,
                "db_create_file_metadata rejects null context");
  expect_int_eq(db_create_file_metadata(ctx, NULL, &metadata_id), -1,
                "db_create_file_metadata rejects null metadata");
  expect_int_eq(db_find_file_metadata_by_path(NULL, report_path,
                                              strlen(report_path), &metadata),
                -1, "db_find_file_metadata_by_path rejects null context");
  expect_int_eq(db_find_file_metadata_by_path(ctx, NULL, strlen(report_path),
                                              &metadata),
                -1, "db_find_file_metadata_by_path rejects null path");
  expect_int_eq(db_find_file_metadata_by_path(ctx, report_path,
                                              strlen(report_path), NULL),
                -1, "db_find_file_metadata_by_path rejects null output");
  expect_int_eq(db_list_children(NULL, "/", 1, entries, 4, &count), -1,
                "db_list_children rejects null context");
  expect_int_eq(db_list_children(ctx, NULL, 1, entries, 4, &count), -1,
                "db_list_children rejects null parent path");
  expect_int_eq(db_list_children(ctx, "/", 1, NULL, 1, &count), -1,
                "db_list_children rejects null output buffer");
  expect_int_eq(db_update_file_metadata(NULL, report_path, strlen(report_path),
                                        &metadata),
                -1, "db_update_file_metadata rejects null context");
  expect_int_eq(db_update_file_metadata(ctx, NULL, strlen(report_path),
                                        &metadata),
                -1, "db_update_file_metadata rejects null current path");
  expect_int_eq(db_update_file_metadata(ctx, report_path, strlen(report_path),
                                        NULL),
                -1, "db_update_file_metadata rejects null metadata");
  expect_int_eq(db_delete_file_metadata(NULL, report_path, strlen(report_path)),
                -1, "db_delete_file_metadata rejects null context");
  expect_int_eq(db_delete_file_metadata(ctx, NULL, strlen(report_path)), -1,
                "db_delete_file_metadata rejects null path");

  expect_int_eq(db_find_file_metadata_by_path(ctx, report_path,
                                              strlen(report_path), &metadata),
                0, "db_find_file_metadata_by_path returns not found before insert");

  init_file_metadata(&metadata, docs_path, "docs", alice_id, 1, admins_id, 493,
                     "directory", 1711382400LL, 1711382400LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts docs directory");
  expect_true(metadata_id > 0,
              "db_create_file_metadata returns an id for docs");

  init_file_metadata(&metadata, archive_path, "archive", alice_id, 0, 0, 493,
                     "directory", 1711382401LL, 1711382401LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts archive directory");

  init_file_metadata(&metadata, report_path, "report.txt", alice_id, 1,
                     admins_id, 420, "file", 1711382402LL, 1711382402LL);
  metadata.has_wrapped_fek_owner = 1;
  set_blob(metadata.wrapped_fek_owner, &metadata.wrapped_fek_owner_len,
           owner_fek, sizeof(owner_fek));
  metadata.has_wrapped_fek_group = 1;
  set_blob(metadata.wrapped_fek_group, &metadata.wrapped_fek_group_len,
           group_fek, sizeof(group_fek));
  metadata.has_wrapped_fek_other = 1;
  set_blob(metadata.wrapped_fek_other, &metadata.wrapped_fek_other_len,
           other_fek, sizeof(other_fek));
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts report file");

  init_file_metadata(&metadata, notes_path, "notes.txt", alice_id, 1, staff_id,
                     420, "file", 1711382403LL, 1711382403LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts notes file");

  init_file_metadata(&metadata, readme_path, "readme.md", bob_id, 0, 0, 420,
                     "file", 1711382404LL, 1711382404LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts readme file");

  init_file_metadata(&metadata, old_path, "old.txt", alice_id, 0, 0, 420,
                     "file", 1711382405LL, 1711382405LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), 0,
                "db_create_file_metadata inserts nested old file");

  init_file_metadata(&metadata, report_path, "duplicate.txt", alice_id, 0, 0,
                     420, "file", 1711382406LL, 1711382406LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), -1,
                "db_create_file_metadata rejects duplicate paths");

  init_file_metadata(&metadata, "/bad-owner", "bad-owner", 9999, 0, 0, 420,
                     "file", 1711382407LL, 1711382407LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), -1,
                "db_create_file_metadata rejects invalid owner ids");

  init_file_metadata(&metadata, "/bad-group", "bad-group", alice_id, 1, 9999,
                     420, "file", 1711382408LL, 1711382408LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), -1,
                "db_create_file_metadata rejects invalid group ids");

  init_file_metadata(&metadata, "/bad-type", "bad-type", alice_id, 0, 0, 420,
                     "symlink", 1711382409LL, 1711382409LL);
  expect_int_eq(db_create_file_metadata(ctx, &metadata, &metadata_id), -1,
                "db_create_file_metadata rejects invalid object types");

  memset(&metadata, 0, sizeof(metadata));
  expect_int_eq(db_find_file_metadata_by_path(ctx, report_path,
                                              strlen(report_path), &metadata),
                1, "db_find_file_metadata_by_path returns stored report row");
  expect_size_eq(metadata.path_len, strlen(report_path),
                 "db_find_file_metadata_by_path returns report path length");
  expect_blob_eq(metadata.path, (const unsigned char*)report_path,
                 strlen(report_path),
                 "db_find_file_metadata_by_path returns report path");
  expect_string_eq(metadata.object_type, "file",
                   "db_find_file_metadata_by_path returns report type");
  expect_int_eq(metadata.owner_id, alice_id,
                "db_find_file_metadata_by_path returns report owner");
  expect_int_eq(metadata.group_id, admins_id,
                "db_find_file_metadata_by_path returns report group id");
  expect_true(metadata.has_group_id,
              "db_find_file_metadata_by_path marks group id present");
  expect_true(metadata.has_wrapped_fek_owner,
              "db_find_file_metadata_by_path marks owner FEK present");
  expect_blob_eq(metadata.wrapped_fek_owner, owner_fek, sizeof(owner_fek),
                 "db_find_file_metadata_by_path returns owner FEK");

  count = 0;
  memset(entries, 0, sizeof(entries));
  expect_int_eq(db_list_children(ctx, "/", 1, entries, 4, &count), 0,
                "db_list_children returns root children");
  expect_size_eq(count, 2, "db_list_children returns two root children");
  expect_blob_eq(entries[0].name, (const unsigned char*)"docs", 4,
                 "db_list_children orders root children by name");
  expect_blob_eq(entries[1].name, (const unsigned char*)"readme.md", 9,
                 "db_list_children includes readme at root");

  count = 0;
  memset(entries, 0, sizeof(entries));
  expect_int_eq(db_list_children(ctx, docs_path, strlen(docs_path), entries, 4,
                                 &count),
                0, "db_list_children returns docs children");
  expect_size_eq(count, 3, "db_list_children returns three docs children");
  expect_blob_eq(entries[0].name, (const unsigned char*)"archive", 7,
                 "db_list_children includes archive first");
  expect_blob_eq(entries[1].name, (const unsigned char*)"notes.txt", 9,
                 "db_list_children includes notes second");
  expect_blob_eq(entries[2].name, (const unsigned char*)"report.txt", 10,
                 "db_list_children includes report third");

  memset(&metadata, 0, sizeof(metadata));
  init_file_metadata(&metadata, report_path, "report.txt", alice_id, 1,
                     admins_id, 384, "file", 1711382402LL, 1711382500LL);
  metadata.has_wrapped_fek_owner = 1;
  set_blob(metadata.wrapped_fek_owner, &metadata.wrapped_fek_owner_len,
           updated_owner_fek, sizeof(updated_owner_fek));
  metadata.has_wrapped_fek_group = 1;
  set_blob(metadata.wrapped_fek_group, &metadata.wrapped_fek_group_len,
           updated_group_fek, sizeof(updated_group_fek));
  metadata.has_wrapped_fek_other = 1;
  set_blob(metadata.wrapped_fek_other, &metadata.wrapped_fek_other_len,
           updated_other_fek, sizeof(updated_other_fek));
  expect_int_eq(db_update_file_metadata(ctx, report_path, strlen(report_path),
                                        &metadata),
                1, "db_update_file_metadata updates report row");

  memset(&metadata, 0, sizeof(metadata));
  expect_int_eq(db_find_file_metadata_by_path(ctx, report_path,
                                              strlen(report_path), &metadata),
                1, "db_find_file_metadata_by_path returns updated report row");
  expect_int_eq(metadata.mode_bits, 384,
                "db_update_file_metadata updates mode bits");
  expect_ll_eq(metadata.updated_at, 1711382500LL,
               "db_update_file_metadata updates updated_at");
  expect_blob_eq(metadata.wrapped_fek_owner, updated_owner_fek,
                 sizeof(updated_owner_fek),
                 "db_update_file_metadata updates owner FEK");
  expect_blob_eq(metadata.wrapped_fek_group, updated_group_fek,
                 sizeof(updated_group_fek),
                 "db_update_file_metadata updates group FEK");
  expect_blob_eq(metadata.wrapped_fek_other, updated_other_fek,
                 sizeof(updated_other_fek),
                 "db_update_file_metadata updates other FEK");

  init_file_metadata(&metadata, "/missing.txt", "missing.txt", alice_id, 0, 0,
                     420, "file", 1711382600LL, 1711382600LL);
  expect_int_eq(db_update_file_metadata(ctx, "/does-not-exist",
                                        strlen("/does-not-exist"), &metadata),
                0, "db_update_file_metadata returns not found for unknown path");

  expect_int_eq(db_delete_file_metadata(ctx, readme_path, strlen(readme_path)),
                1, "db_delete_file_metadata removes stored metadata");
  expect_int_eq(db_find_file_metadata_by_path(ctx, readme_path,
                                              strlen(readme_path), &metadata),
                0, "db_delete_file_metadata removes readme row");
  expect_int_eq(db_delete_file_metadata(ctx, readme_path, strlen(readme_path)),
                0, "db_delete_file_metadata returns not found for missing path");
}

static void test_transaction_wrappers(const char* db_path,
                                      const char* schema_path,
                                      server_context_t* ctx) {
  db_group_t group;
  server_context_t second_ctx;

  memset(&group, 0, sizeof(group));
  memset(&second_ctx, 0, sizeof(second_ctx));

  expect_int_eq(db_begin_transaction(NULL), -1,
                "db_begin_transaction rejects null context");
  expect_int_eq(db_commit(NULL), -1, "db_commit rejects null context");
  expect_int_eq(db_rollback(NULL), -1, "db_rollback rejects null context");

  expect_int_eq(db_begin_transaction(ctx), 0,
                "db_begin_transaction starts a transaction");
  expect_int_eq(db_create_group(ctx, "txn_rollback", NULL), 0,
                "transaction can insert rollback group");
  expect_int_eq(db_find_group_by_name(ctx, "txn_rollback", &group), 1,
                "rollback group is visible before rollback");
  expect_int_eq(db_rollback(ctx), 0,
                "db_rollback reverts uncommitted writes");
  expect_int_eq(db_find_group_by_name(ctx, "txn_rollback", &group), 0,
                "rollback removes uncommitted group");

  expect_int_eq(db_begin_transaction(ctx), 0,
                "db_begin_transaction starts a second transaction");
  expect_int_eq(db_create_group(ctx, "txn_commit", NULL), 0,
                "transaction can insert commit group");
  expect_int_eq(db_commit(ctx), 0,
                "db_commit persists writes to the database");

  second_ctx.db_path = db_path;
  second_ctx.schema_path = schema_path;
  expect_int_eq(db_init(&second_ctx), 0,
                "db_init opens a second handle for transaction checks");
  expect_int_eq(db_find_group_by_name(&second_ctx, "txn_commit", &group), 1,
                "db_commit persists writes across handles");
  db_cleanup(&second_ctx);
  expect_true(second_ctx.db == NULL,
              "db_cleanup clears second transaction test handle");
}

int main(int argc, char* argv[]) {
  server_context_t ctx;

  if (argc != 3) {
    fprintf(stderr, "usage: %s <db-path> <schema-path>\n", argv[0]);
    return 2;
  }

  test_invalid_init_inputs(argv[2]);

  memset(&ctx, 0, sizeof(ctx));
  ctx.db_path = argv[1];
  ctx.schema_path = argv[2];

  expect_int_eq(db_init(&ctx), 0,
                "db_init opens test database and applies schema");
  expect_true(db_handle(&ctx) != NULL,
              "db_handle returns sqlite handle after init");

  test_user_wrappers(&ctx);
  test_group_wrappers(&ctx);
  test_group_membership_wrappers(&ctx);
  test_file_metadata_wrappers(&ctx);
  test_transaction_wrappers(argv[1], argv[2], &ctx);

  db_cleanup(&ctx);
  expect_true(ctx.db == NULL, "db_cleanup clears sqlite handle");
  expect_true(db_handle(&ctx) == NULL,
              "db_handle returns NULL after cleanup");

  printf("\nSummary: %d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
