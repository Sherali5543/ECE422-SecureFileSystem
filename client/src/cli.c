#include "cli_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "encryption.h"
#include "http.h"

#define MAX_ARGS 5
#define CLIENT_RESPONSE_JSON_MAX 16384
#define GROUPS_SHARED_SCOPE "__sfs_groups_root__"

typedef struct {
    http_message_t* msg;
    unsigned char* body;
    size_t body_len;
} client_response_t;

typedef struct {
    int has_group;
    char group_name[SESSION_GROUP_NAME_MAX];
} path_scope_info_t;

typedef struct {
    size_t directories_scanned;
    size_t files_scanned;
    size_t corrupted_names;
    size_t corrupted_files;
    size_t scan_errors;
} integrity_report_t;

static int load_group_key(SSL* ssl, Session* session, const char* group_name,
                          unsigned char* out_key);

static int derive_groups_root_name_key(
    unsigned char out_key[crypto_secretbox_KEYBYTES]) {
    static const unsigned char label[] = "sfs-groups-root-v1";

    if (out_key == NULL) {
        return -1;
    }

    if (crypto_generichash(out_key, crypto_secretbox_KEYBYTES, label,
                           sizeof(label) - 1, NULL, 0) != 0) {
        return -1;
    }

    return 0;
}

static void cleanup_response(client_response_t* response) {
    if (response == NULL) {
        return;
    }

    free(response->body);
    response->body = NULL;
    response->body_len = 0;
    if (response->msg != NULL) {
        destroy_message(response->msg);
        response->msg = NULL;
    }
}

static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_encode(const unsigned char* bytes, size_t len, char* out,
                      size_t out_len) {
    static const char hex_chars[] = "0123456789abcdef";

    if (bytes == NULL || out == NULL || out_len < len * 2 + 1) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[bytes[i] >> 4];
        out[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
    return 0;
}

static int hex_decode(const char* hex, unsigned char* out, size_t out_len,
                      size_t* decoded_len) {
    size_t hex_len = 0;

    if (hex == NULL || out == NULL || decoded_len == NULL) {
        return -1;
    }

    hex_len = strlen(hex);
    if ((hex_len % 2) != 0 || out_len < hex_len / 2) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_digit_value(hex[i * 2]);
        int lo = hex_digit_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    *decoded_len = hex_len / 2;
    return 0;
}

static int read_file_bytes(const char* path, unsigned char** out_buf,
                           size_t* out_len) {
    struct stat st;
    int fd = -1;
    unsigned char* buf = NULL;
    size_t total = 0;

    if (path == NULL || out_buf == NULL || out_len == NULL) {
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    buf = malloc((size_t)st.st_size + 1);
    if (buf == NULL) {
        close(fd);
        return -1;
    }

    while (total < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + total, (size_t)st.st_size - total);
        if (n <= 0) {
            perror("read");
            free(buf);
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }

    close(fd);
    buf[total] = '\0';
    *out_buf = buf;
    *out_len = total;
    return 0;
}

static int write_temp_file(const unsigned char* buf, size_t len,
                           const char* prefix, char** out_path) {
    char template_buf[128];
    int fd = -1;

    if (out_path == NULL || prefix == NULL || (buf == NULL && len > 0)) {
        return -1;
    }

    snprintf(template_buf, sizeof(template_buf), "/tmp/%sXXXXXX", prefix);
    fd = mkstemp(template_buf);
    if (fd < 0) {
        perror("mkstemp");
        return -1;
    }

    if (len > 0 && write(fd, buf, len) != (ssize_t)len) {
        perror("write");
        close(fd);
        unlink(template_buf);
        return -1;
    }

    close(fd);
    *out_path = strdup(template_buf);
    return *out_path == NULL ? -1 : 0;
}

static int parse_write_command_input(char* input, char** out_remote_path,
                                     char** out_text) {
    char* cursor = NULL;

    if (input == NULL || out_remote_path == NULL || out_text == NULL) {
        return -1;
    }

    *out_remote_path = NULL;
    *out_text = NULL;

    if (strncmp(input, "write", 5) != 0 || input[5] == '\0') {
        return -1;
    }

    cursor = input + 5;
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if (*cursor == '\0') {
        return -1;
    }

    *out_remote_path = cursor;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
        cursor++;
    }
    if (*cursor == '\0') {
        return -1;
    }

    *cursor = '\0';
    cursor++;
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if (*cursor == '\0') {
        return -1;
    }

    *out_text = cursor;
    return 0;
}

static int split_parent_child(const char* fullpath, char* parent,
                              size_t parent_sz, char* name, size_t name_sz) {
    const char* slash = NULL;
    size_t parent_len = 0;
    size_t name_len = 0;

    if (!fullpath || fullpath[0] != '/') {
        return -1;
    }

    slash = strrchr(fullpath, '/');
    if (!slash || *(slash + 1) == '\0') {
        return -1;
    }

    name_len = strlen(slash + 1);
    if (name_len == 0 || name_len >= name_sz) {
        return -1;
    }

    strncpy(name, slash + 1, name_sz - 1);
    name[name_sz - 1] = '\0';

    if (slash == fullpath) {
        if (parent_sz < 2) {
            return -1;
        }
        strcpy(parent, "/");
        return 0;
    }

    parent_len = (size_t)(slash - fullpath);
    if (parent_len >= parent_sz) {
        return -1;
    }

    memcpy(parent, fullpath, parent_len);
    parent[parent_len] = '\0';
    return 0;
}

static int normalize_path(const char* cwd, const char* input, char* out,
                          size_t out_len) {
    char combined[SESSION_PATH_MAX * 2];
    char work[SESSION_PATH_MAX * 2];
    char normalized[SESSION_PATH_MAX];
    char* token = NULL;
    char* saveptr = NULL;

    if (cwd == NULL || input == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    if (input[0] == '/') {
        snprintf(combined, sizeof(combined), "%s", input);
    } else if (strcmp(cwd, "/") == 0) {
        snprintf(combined, sizeof(combined), "/%s", input);
    } else {
        snprintf(combined, sizeof(combined), "%s/%s", cwd, input);
    }

    strncpy(work, combined, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';
    normalized[0] = '\0';

    token = strtok_r(work, "/", &saveptr);
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
            token = strtok_r(NULL, "/", &saveptr);
            continue;
        }
        if (strcmp(token, "..") == 0) {
            char* last_slash = strrchr(normalized, '/');
            if (last_slash != NULL) {
                *last_slash = '\0';
            }
            token = strtok_r(NULL, "/", &saveptr);
            continue;
        }

        if (normalized[0] == '\0') {
            snprintf(normalized, sizeof(normalized), "/%s", token);
        } else {
            size_t current_len = strlen(normalized);
            snprintf(normalized + current_len, sizeof(normalized) - current_len,
                     "/%s", token);
        }

        token = strtok_r(NULL, "/", &saveptr);
    }

    if (normalized[0] == '\0') {
        strncpy(normalized, "/", sizeof(normalized) - 1);
        normalized[sizeof(normalized) - 1] = '\0';
    }

    if (strlen(normalized) >= out_len) {
        return -1;
    }

    strncpy(out, normalized, out_len - 1);
    out[out_len - 1] = '\0';
    return 0;
}

static int is_parent_prefix(const char* parent, const char* child) {
    size_t parent_len = 0;

    if (parent == NULL || child == NULL) {
        return 0;
    }
    if (strcmp(parent, "/") == 0) {
        return child[0] == '/';
    }

    parent_len = strlen(parent);
    return strncmp(parent, child, parent_len) == 0 &&
           (child[parent_len] == '/' || child[parent_len] == '\0');
}

static int build_child_path(const char* parent, const char* name, char* out,
                            size_t out_len) {
    if (parent == NULL || name == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    if (strcmp(parent, "/") == 0) {
        return snprintf(out, out_len, "/%s", name) >= 0 &&
                       (size_t)snprintf(out, out_len, "/%s", name) < out_len
                   ? 0
                   : -1;
    }

    return snprintf(out, out_len, "%s/%s", parent, name) >= 0 &&
                   (size_t)snprintf(out, out_len, "%s/%s", parent, name) < out_len
               ? 0
               : -1;
}

static void print_response_error(const char* action,
                                 const client_response_t* response) {
    if (response == NULL || response->msg == NULL) {
        fprintf(stderr, "%s failed: no response\n", action);
        return;
    }

    fprintf(stderr, "%s failed: HTTP %d %s\n", action, response->msg->status_code,
            response->msg->reason);
    if (response->body != NULL && response->body_len > 0) {
        fprintf(stderr, "%.*s\n", (int)response->body_len, response->body);
    }
}

static int perform_request(SSL* ssl, http_method_t method, const char* path,
                           const char* query, const char* auth_token,
                           http_content_type_t content_type,
                           const unsigned char* body, size_t body_len,
                           client_response_t* out_response) {
    http_message_t* request = NULL;

    if (ssl == NULL || path == NULL || out_response == NULL) {
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));
    request = init_request();
    if (request == NULL) {
        return -1;
    }

    request->method = method;
    strncpy(request->path, path, sizeof(request->path) - 1);
    request->path[sizeof(request->path) - 1] = '\0';
    if (query != NULL) {
        strncpy(request->query, query, sizeof(request->query) - 1);
        request->query[sizeof(request->query) - 1] = '\0';
    }
    if (auth_token != NULL) {
        strncpy(request->auth_token, auth_token, sizeof(request->auth_token) - 1);
        request->auth_token[sizeof(request->auth_token) - 1] = '\0';
    }
    request->content_type = content_type;
    request->content_length = body_len;
    strncpy(request->connection, "close", sizeof(request->connection) - 1);
    request->connection[sizeof(request->connection) - 1] = '\0';

    send_request(ssl, request);
    if (body_len > 0 &&
        tls_write(ssl, (void*)body, body_len) != (ssize_t)body_len) {
        destroy_message(request);
        return -1;
    }
    destroy_message(request);

    out_response->msg = read_response(ssl);
    if (out_response->msg == NULL) {
        return -1;
    }

    out_response->body_len = out_response->msg->content_length;
    if (out_response->body_len > 0) {
        out_response->body = malloc(out_response->body_len + 1);
        if (out_response->body == NULL) {
            cleanup_response(out_response);
            return -1;
        }
        if (read_message_body(ssl, out_response->msg, out_response->body,
                              out_response->body_len) !=
            (ssize_t)out_response->body_len) {
            cleanup_response(out_response);
            return -1;
        }
        out_response->body[out_response->body_len] = '\0';
    }

    return 0;
}

static int cache_path_scope(Session* session, const char* logical_path,
                            const char* group_name) {
    size_t i = 0;
    size_t slot = SESSION_MAX_PATH_SCOPES;

    if (session == NULL || logical_path == NULL) {
        return -1;
    }

    for (i = 0; i < SESSION_MAX_PATH_SCOPES; i++) {
        if (session->path_scopes[i].in_use &&
            strcmp(session->path_scopes[i].logical_path, logical_path) == 0) {
            session->path_scopes[i].has_group = group_name != NULL;
            if (group_name != NULL) {
                strncpy(session->path_scopes[i].group_name, group_name,
                        sizeof(session->path_scopes[i].group_name) - 1);
                session->path_scopes[i]
                    .group_name[sizeof(session->path_scopes[i].group_name) - 1] =
                    '\0';
            } else {
                session->path_scopes[i].group_name[0] = '\0';
            }
            return 0;
        }
        if (!session->path_scopes[i].in_use && slot == SESSION_MAX_PATH_SCOPES) {
            slot = i;
        }
    }

    if (slot == SESSION_MAX_PATH_SCOPES) {
        return -1;
    }

    session->path_scopes[slot].in_use = 1;
    strncpy(session->path_scopes[slot].logical_path, logical_path,
            sizeof(session->path_scopes[slot].logical_path) - 1);
    session->path_scopes[slot]
        .logical_path[sizeof(session->path_scopes[slot].logical_path) - 1] = '\0';
    session->path_scopes[slot].has_group = group_name != NULL;
    if (group_name != NULL) {
        strncpy(session->path_scopes[slot].group_name, group_name,
                sizeof(session->path_scopes[slot].group_name) - 1);
        session->path_scopes[slot]
            .group_name[sizeof(session->path_scopes[slot].group_name) - 1] = '\0';
    } else {
        session->path_scopes[slot].group_name[0] = '\0';
    }
    return 0;
}

static void initialize_session_scopes(Session* session) {
    char home_path[SESSION_PATH_MAX];

    if (session == NULL) {
        return;
    }

    cache_path_scope(session, "/", NULL);
    cache_path_scope(session, "/home", NULL);
    cache_path_scope(session, "/groups", GROUPS_SHARED_SCOPE);
    if (session->username != NULL &&
        snprintf(home_path, sizeof(home_path), "/home/%s", session->username) > 0 &&
        strlen(home_path) < sizeof(home_path)) {
        cache_path_scope(session, home_path, NULL);
    }
    cache_path_scope(session, session->cwd, NULL);
}

static int lookup_path_scope(Session* session, const char* logical_path,
                             path_scope_info_t* out_scope) {
    size_t i = 0;
    size_t best_len = 0;

    if (session == NULL || logical_path == NULL || out_scope == NULL) {
        return -1;
    }

    memset(out_scope, 0, sizeof(*out_scope));
    for (i = 0; i < SESSION_MAX_PATH_SCOPES; i++) {
        size_t len = 0;

        if (!session->path_scopes[i].in_use ||
            !is_parent_prefix(session->path_scopes[i].logical_path, logical_path)) {
            continue;
        }

        len = strlen(session->path_scopes[i].logical_path);
        if (len < best_len) {
            continue;
        }

        best_len = len;
        out_scope->has_group = session->path_scopes[i].has_group;
        if (session->path_scopes[i].has_group) {
            strncpy(out_scope->group_name, session->path_scopes[i].group_name,
                    sizeof(out_scope->group_name) - 1);
            out_scope->group_name[sizeof(out_scope->group_name) - 1] = '\0';
        } else {
            out_scope->group_name[0] = '\0';
        }
    }

    return 0;
}

static int resolve_scope_key(SSL* ssl, Session* session,
                             const path_scope_info_t* scope,
                             unsigned char* out_key) {
    if (session == NULL || scope == NULL || out_key == NULL) {
        return -1;
    }

    if (scope->has_group) {
        if (strcmp(scope->group_name, GROUPS_SHARED_SCOPE) == 0) {
            return derive_groups_root_name_key(out_key);
        }
        return load_group_key(ssl, session, scope->group_name, out_key);
    }

    return derive_private_name_key(session->user_keys, out_key);
}

static int encrypt_logical_path(SSL* ssl, Session* session,
                                const char* logical_path, char* out_path,
                                size_t out_len) {
    char work[SESSION_PATH_MAX];
    char plaintext_parent[SESSION_PATH_MAX];
    char current_plain[SESSION_PATH_MAX];
    char* token = NULL;
    char* saveptr = NULL;
    path_scope_info_t scope = {0};
    unsigned char name_key[crypto_secretbox_KEYBYTES];

    if (ssl == NULL || session == NULL || logical_path == NULL || out_path == NULL ||
        out_len == 0) {
        return -1;
    }

    if (strcmp(logical_path, "/") == 0) {
        if (out_len < 2) {
            return -1;
        }
        strcpy(out_path, "/");
        return 0;
    }

    strncpy(work, logical_path, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';
    strncpy(plaintext_parent, "/", sizeof(plaintext_parent) - 1);
    plaintext_parent[sizeof(plaintext_parent) - 1] = '\0';
    out_path[0] = '\0';

    token = strtok_r(work, "/", &saveptr);
    while (token != NULL) {
        char* enc_component = NULL;
        size_t current_len = strlen(out_path);

        if (strcmp(plaintext_parent, "/") == 0 && strcmp(token, "groups") == 0) {
            if (derive_groups_root_name_key(name_key) != 0) {
                return -1;
            }
        } else {
            if (lookup_path_scope(session, plaintext_parent, &scope) != 0 ||
                resolve_scope_key(ssl, session, &scope, name_key) != 0) {
                return -1;
            }
        }

        enc_component = encrypt_name_component_hex(name_key, token);
        if (enc_component == NULL) {
            return -1;
        }

        if (current_len == 0) {
            if (snprintf(out_path, out_len, "/%s", enc_component) < 0 ||
                strlen(out_path) >= out_len) {
                free(enc_component);
                return -1;
            }
        } else {
            if (snprintf(out_path + current_len, out_len - current_len, "/%s",
                         enc_component) < 0 ||
                strlen(out_path) >= out_len) {
                free(enc_component);
                return -1;
            }
        }

        free(enc_component);
        if (build_child_path(plaintext_parent, token, current_plain,
                             sizeof(current_plain)) != 0) {
            return -1;
        }
        if (strcmp(plaintext_parent, "/groups") == 0) {
            cache_path_scope(session, current_plain, token);
        }
        strncpy(plaintext_parent, current_plain, sizeof(plaintext_parent) - 1);
        plaintext_parent[sizeof(plaintext_parent) - 1] = '\0';
        token = strtok_r(NULL, "/", &saveptr);
    }

    return 0;
}

static int cache_group_key(Session* session, const char* group_name,
                           const unsigned char* key) {
    size_t i = 0;
    size_t slot = SESSION_MAX_GROUP_KEYS;

    if (session == NULL || group_name == NULL || key == NULL) {
        return -1;
    }

    for (i = 0; i < SESSION_MAX_GROUP_KEYS; i++) {
        if (session->group_keys[i].in_use &&
            strcmp(session->group_keys[i].group_name, group_name) == 0) {
            memcpy(session->group_keys[i].key, key, crypto_secretbox_KEYBYTES);
            return 0;
        }
        if (!session->group_keys[i].in_use && slot == SESSION_MAX_GROUP_KEYS) {
            slot = i;
        }
    }

    if (slot == SESSION_MAX_GROUP_KEYS) {
        return -1;
    }

    session->group_keys[slot].in_use = 1;
    strncpy(session->group_keys[slot].group_name, group_name,
            sizeof(session->group_keys[slot].group_name) - 1);
    session->group_keys[slot].group_name[sizeof(session->group_keys[slot].group_name) - 1] = '\0';
    memcpy(session->group_keys[slot].key, key, crypto_secretbox_KEYBYTES);
    return 0;
}

static int cache_file_key(Session* session, const char* filepath,
                          const unsigned char* key) {
    size_t i = 0;
    size_t slot = SESSION_MAX_FILE_KEYS;

    if (session == NULL || filepath == NULL || key == NULL) {
        return -1;
    }

    for (i = 0; i < SESSION_MAX_FILE_KEYS; i++) {
        if (session->file_keys[i].in_use &&
            strcmp(session->file_keys[i].filepath, filepath) == 0) {
            memcpy(session->file_keys[i].key, key,
                   crypto_secretstream_xchacha20poly1305_KEYBYTES);
            return 0;
        }
        if (!session->file_keys[i].in_use && slot == SESSION_MAX_FILE_KEYS) {
            slot = i;
        }
    }

    if (slot == SESSION_MAX_FILE_KEYS) {
        return -1;
    }

    session->file_keys[slot].in_use = 1;
    strncpy(session->file_keys[slot].filepath, filepath,
            sizeof(session->file_keys[slot].filepath) - 1);
    session->file_keys[slot].filepath[sizeof(session->file_keys[slot].filepath) - 1] = '\0';
    memcpy(session->file_keys[slot].key, key,
           crypto_secretstream_xchacha20poly1305_KEYBYTES);
    return 0;
}

static int get_cached_group_key(Session* session, const char* group_name,
                                unsigned char* out_key) {
    size_t i = 0;

    if (session == NULL || group_name == NULL || out_key == NULL) {
        return -1;
    }

    for (i = 0; i < SESSION_MAX_GROUP_KEYS; i++) {
        if (session->group_keys[i].in_use &&
            strcmp(session->group_keys[i].group_name, group_name) == 0) {
            memcpy(out_key, session->group_keys[i].key, crypto_secretbox_KEYBYTES);
            return 0;
        }
    }

    return -1;
}

static int get_cached_file_key(Session* session, const char* filepath,
                               unsigned char* out_key) {
    size_t i = 0;

    if (session == NULL || filepath == NULL || out_key == NULL) {
        return -1;
    }

    for (i = 0; i < SESSION_MAX_FILE_KEYS; i++) {
        if (session->file_keys[i].in_use &&
            strcmp(session->file_keys[i].filepath, filepath) == 0) {
            memcpy(out_key, session->file_keys[i].key,
                   crypto_secretstream_xchacha20poly1305_KEYBYTES);
            return 0;
        }
    }

    return -1;
}

static int fetch_user_public_encryption_key(SSL* ssl, Session* session,
                                            const char* username,
                                            unsigned char* out_key) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* key_json = NULL;
    char query[HTTP_MAX_QUERY_LEN];
    size_t key_len = 0;
    int rc = -1;

    if (ssl == NULL || session == NULL || username == NULL || out_key == NULL) {
        return -1;
    }

    snprintf(query, sizeof(query), "username=%s", username);
    if (perform_request(ssl, GET, "/users/keys", query, session->token, NONE,
                        NULL, 0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("fetch user keys", &response);
        goto cleanup;
    }

    json = cJSON_Parse((char*)response.body);
    if (json == NULL) {
        goto cleanup;
    }

    key_json = cJSON_GetObjectItemCaseSensitive(json, "public_encryption_key");
    if (!cJSON_IsString(key_json) || key_json->valuestring == NULL ||
        hex_decode(key_json->valuestring, out_key, crypto_box_PUBLICKEYBYTES,
                   &key_len) != 0 ||
        key_len != crypto_box_PUBLICKEYBYTES) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    cJSON_Delete(json);
    cleanup_response(&response);
    return rc;
}

static int fetch_group_name_by_id(SSL* ssl, Session* session, int group_id,
                                  char* out_group_name, size_t out_size) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* groups_json = NULL;
    int rc = -1;

    if (ssl == NULL || session == NULL || out_group_name == NULL || out_size == 0) {
        return -1;
    }

    if (perform_request(ssl, GET, "/groups", NULL, session->token, NONE, NULL,
                        0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("list groups", &response);
        goto cleanup;
    }

    json = cJSON_Parse((char*)response.body);
    if (json == NULL) {
        goto cleanup;
    }

    groups_json = cJSON_GetObjectItemCaseSensitive(json, "groups");
    if (!cJSON_IsArray(groups_json)) {
        goto cleanup;
    }

    cJSON* item = NULL;
    cJSON_ArrayForEach(item, groups_json) {
        cJSON* group_id_json = cJSON_GetObjectItemCaseSensitive(item, "group_id");
        cJSON* name_json = cJSON_GetObjectItemCaseSensitive(item, "group_name");

        if (!cJSON_IsNumber(group_id_json) || !cJSON_IsString(name_json) ||
            name_json->valuestring == NULL) {
            continue;
        }
        if (group_id_json->valueint == group_id) {
            strncpy(out_group_name, name_json->valuestring, out_size - 1);
            out_group_name[out_size - 1] = '\0';
            rc = 0;
            break;
        }
    }

cleanup:
    cJSON_Delete(json);
    cleanup_response(&response);
    return rc;
}

static int fetch_metadata_for_path(SSL* ssl, Session* session, const char* path,
                                   client_response_t* out_response) {
    char encrypted_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];

    if (ssl == NULL || session == NULL || path == NULL || out_response == NULL) {
        return -1;
    }

    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_path);
    return perform_request(ssl, GET, "/files/meta", query, session->token, NONE,
                           NULL, 0, out_response);
}

static int fetch_group_info_for_path(SSL* ssl, Session* session,
                                     const char* path, int* out_group_id,
                                     int* out_has_group_id) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* group_id_json = NULL;
    int rc = -1;

    if (ssl == NULL || session == NULL || path == NULL || out_group_id == NULL ||
        out_has_group_id == NULL) {
        return -1;
    }

    *out_group_id = 0;
    *out_has_group_id = 0;

    if (fetch_metadata_for_path(ssl, session, path, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("fetch path metadata", &response);
        goto cleanup;
    }

    json = cJSON_Parse((char*)response.body);
    if (json == NULL) {
        goto cleanup;
    }

    group_id_json = cJSON_GetObjectItemCaseSensitive(json, "group_id");
    if (cJSON_IsNumber(group_id_json)) {
        *out_group_id = group_id_json->valueint;
        *out_has_group_id = 1;
    }
    rc = 0;

cleanup:
    cJSON_Delete(json);
    cleanup_response(&response);
    return rc;
}

static int load_group_key(SSL* ssl, Session* session, const char* group_name,
                          unsigned char* out_key) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* wrapped_key_json = NULL;
    unsigned char wrapped_group_key[crypto_box_SEALBYTES +
                                    crypto_secretstream_xchacha20poly1305_KEYBYTES];
    size_t wrapped_group_key_len = 0;
    char query[HTTP_MAX_QUERY_LEN];
    char* group_key = NULL;
    int rc = -1;

    if (ssl == NULL || session == NULL || group_name == NULL || out_key == NULL) {
        return -1;
    }

    if (get_cached_group_key(session, group_name, out_key) == 0) {
        return 0;
    }

    snprintf(query, sizeof(query), "group_name=%s", group_name);
    if (perform_request(ssl, GET, "/groups/key", query, session->token, NONE,
                        NULL, 0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("fetch group key", &response);
        goto cleanup;
    }

    json = cJSON_Parse((char*)response.body);
    if (json == NULL) {
        goto cleanup;
    }

    wrapped_key_json = cJSON_GetObjectItemCaseSensitive(json, "wrapped_group_key");
    if (!cJSON_IsString(wrapped_key_json) || wrapped_key_json->valuestring == NULL ||
        hex_decode(wrapped_key_json->valuestring, wrapped_group_key,
                   sizeof(wrapped_group_key), &wrapped_group_key_len) != 0) {
        goto cleanup;
    }

    group_key = decrypt_wrapped_user_key(session->user_keys,
                                         (char*)wrapped_group_key);
    if (group_key == NULL) {
        goto cleanup;
    }

    memcpy(out_key, group_key, crypto_secretbox_KEYBYTES);
    cache_group_key(session, group_name, out_key);
    rc = 0;

cleanup:
    free(group_key);
    cJSON_Delete(json);
    cleanup_response(&response);
    return rc;
}

static int resolve_file_key_from_read(SSL* ssl, Session* session,
                                      const char* filepath,
                                      const char* wrapped_fek_hex,
                                      const char* fek_scope,
                                      unsigned char* out_key) {
    unsigned char wrapped_fek[HTTP_MAX_HEADER_VALUE / 2];
    size_t wrapped_fek_len = 0;
    char group_name[SESSION_GROUP_NAME_MAX];
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    char* unwrapped_key = NULL;

    if (session == NULL || filepath == NULL || wrapped_fek_hex == NULL ||
        fek_scope == NULL || out_key == NULL) {
        return -1;
    }

    if (hex_decode(wrapped_fek_hex, wrapped_fek, sizeof(wrapped_fek),
                   &wrapped_fek_len) != 0) {
        return -1;
    }

    if (strcmp(fek_scope, "owner") == 0) {
        unwrapped_key =
            decrypt_wrapped_user_key(session->user_keys, (char*)wrapped_fek);
    } else if (strcmp(fek_scope, "group") == 0) {
        int group_id = 0;
        int has_group_id = 0;

        if (fetch_group_info_for_path(ssl, session, filepath, &group_id,
                                      &has_group_id) != 0 || !has_group_id ||
            fetch_group_name_by_id(ssl, session, group_id, group_name,
                                   sizeof(group_name)) != 0 ||
            load_group_key(ssl, session, group_name, group_key) != 0) {
            return -1;
        }

        unwrapped_key =
            decrypt_file_group_key((char*)group_key, (char*)wrapped_fek);
    } else {
        fprintf(stderr, "Scope '%s' is not supported by the client yet\n",
                fek_scope);
        return -1;
    }

    if (unwrapped_key == NULL) {
        return -1;
    }

    memcpy(out_key, unwrapped_key,
           crypto_secretstream_xchacha20poly1305_KEYBYTES);
    free(unwrapped_key);
    cache_file_key(session, filepath, out_key);
    return 0;
}

static int fetch_file_key(SSL* ssl, Session* session, const char* filepath,
                          unsigned char* out_key) {
    client_response_t response = {0};
    char encrypted_filepath[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    int rc = -1;

    if (ssl == NULL || session == NULL || filepath == NULL || out_key == NULL) {
        return -1;
    }

    if (get_cached_file_key(session, filepath, out_key) == 0) {
        return 0;
    }

    if (encrypt_logical_path(ssl, session, filepath, encrypted_filepath,
                             sizeof(encrypted_filepath)) != 0) {
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_filepath);
    if (perform_request(ssl, GET, "/files/contents", query, session->token, NONE,
                        NULL, 0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("fetch file key", &response);
        goto cleanup;
    }
    if (response.msg->x_wrapped_fek[0] == '\0' || response.msg->x_fek_scope[0] == '\0') {
        goto cleanup;
    }

    rc = resolve_file_key_from_read(ssl, session, filepath,
                                    response.msg->x_wrapped_fek,
                                    response.msg->x_fek_scope, out_key);

cleanup:
    cleanup_response(&response);
    return rc;
}

static int resolve_directory_name_key(SSL* ssl, Session* session,
                                      const char* directory_path,
                                      unsigned char* out_key,
                                      path_scope_info_t* out_scope) {
    path_scope_info_t scope = {0};

    if (ssl == NULL || session == NULL || directory_path == NULL ||
        out_key == NULL) {
        return -1;
    }

    if (lookup_path_scope(session, directory_path, &scope) != 0 ||
        resolve_scope_key(ssl, session, &scope, out_key) != 0) {
        return -1;
    }

    if (out_scope != NULL) {
        *out_scope = scope;
    }
    return 0;
}

static int verify_owned_file_integrity(SSL* ssl, Session* session,
                                       const char* remote_path,
                                       integrity_report_t* report) {
    client_response_t response = {0};
    char encrypted_remote_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    char* encrypted_path = NULL;
    char* decrypted_path = NULL;
    unsigned char* plaintext = NULL;
    size_t plaintext_len = 0;
    int rc = -1;

    if (ssl == NULL || session == NULL || remote_path == NULL || report == NULL) {
        return -1;
    }

    report->files_scanned++;
    if (encrypt_logical_path(ssl, session, remote_path, encrypted_remote_path,
                             sizeof(encrypted_remote_path)) != 0) {
        report->scan_errors++;
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_remote_path);
    if (perform_request(ssl, GET, "/files/contents", query, session->token, NONE,
                        NULL, 0, &response) != 0) {
        report->scan_errors++;
        return -1;
    }
    if (response.msg->status_code != 200) {
        report->corrupted_files++;
        cleanup_response(&response);
        return -1;
    }

    if (resolve_file_key_from_read(ssl, session, remote_path,
                                   response.msg->x_wrapped_fek,
                                   response.msg->x_fek_scope, file_key) != 0) {
        report->corrupted_files++;
        cleanup_response(&response);
        return -1;
    }

    if (write_temp_file(response.body, response.body_len, "sfs_integrity_enc_",
                        &encrypted_path) != 0) {
        report->scan_errors++;
        cleanup_response(&response);
        return -1;
    }

    decrypted_path = decrypt_file((char*)file_key, encrypted_path);
    if (decrypted_path == NULL ||
        read_file_bytes(decrypted_path, &plaintext, &plaintext_len) != 0) {
        report->corrupted_files++;
        goto cleanup;
    }

    rc = 0;

cleanup:
    cleanup_response(&response);
    free(plaintext);
    if (encrypted_path != NULL) {
        unlink(encrypted_path);
    }
    if (decrypted_path != NULL) {
        unlink(decrypted_path);
    }
    free(encrypted_path);
    free(decrypted_path);
    return rc;
}

static int scan_directory_integrity(SSL* ssl, Session* session,
                                    const char* path,
                                    integrity_report_t* report) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* entries = NULL;
    char encrypted_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char dir_key[crypto_secretbox_KEYBYTES];
    int rc = -1;

    if (ssl == NULL || session == NULL || path == NULL || report == NULL) {
        return -1;
    }

    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0 ||
        resolve_directory_name_key(ssl, session, path, dir_key, NULL) != 0) {
        report->scan_errors++;
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_path);
    if (perform_request(ssl, GET, "/files", query, session->token, NONE, NULL,
                        0, &response) != 0) {
        report->scan_errors++;
        return -1;
    }
    if (response.msg->status_code != 200) {
        report->scan_errors++;
        cleanup_response(&response);
        return -1;
    }

    report->directories_scanned++;
    json = cJSON_Parse((char*)response.body);
    entries = json ? cJSON_GetObjectItemCaseSensitive(json, "entries") : NULL;
    if (!cJSON_IsArray(entries)) {
        report->scan_errors++;
        goto cleanup;
    }

    cJSON* item = NULL;
    cJSON_ArrayForEach(item, entries) {
        cJSON* name_json = cJSON_GetObjectItemCaseSensitive(item, "name");
        cJSON* type_json = cJSON_GetObjectItemCaseSensitive(item, "object_type");
        cJSON* owner_id_json = cJSON_GetObjectItemCaseSensitive(item, "owner_id");
        cJSON* group_id_json = cJSON_GetObjectItemCaseSensitive(item, "group_id");
        char* decrypted_name = NULL;
        char child_path[SESSION_PATH_MAX];

        if (!cJSON_IsString(name_json) || name_json->valuestring == NULL ||
            !cJSON_IsString(type_json) || type_json->valuestring == NULL) {
            report->scan_errors++;
            continue;
        }

        decrypted_name = decrypt_name_component_hex(dir_key, name_json->valuestring);
        if (decrypted_name == NULL) {
            report->corrupted_names++;
            continue;
        }

        if (build_child_path(path, decrypted_name, child_path,
                             sizeof(child_path)) != 0) {
            free(decrypted_name);
            report->scan_errors++;
            continue;
        }

        if (strcmp(type_json->valuestring, "directory") == 0) {
            if (cJSON_IsNumber(group_id_json)) {
                char group_name[SESSION_GROUP_NAME_MAX];

                if (fetch_group_name_by_id(ssl, session, group_id_json->valueint,
                                           group_name, sizeof(group_name)) == 0) {
                    cache_path_scope(session, child_path, group_name);
                }
            } else {
                path_scope_info_t inherited = {0};
                if (lookup_path_scope(session, path, &inherited) == 0) {
                    cache_path_scope(session, child_path,
                                     inherited.has_group ? inherited.group_name
                                                         : NULL);
                }
            }
            scan_directory_integrity(ssl, session, child_path, report);
        } else if (strcmp(type_json->valuestring, "file") == 0 &&
                   cJSON_IsNumber(owner_id_json) &&
                   owner_id_json->valueint == session->id) {
            verify_owned_file_integrity(ssl, session, child_path, report);
        }

        free(decrypted_name);
    }

    rc = 0;

cleanup:
    cJSON_Delete(json);
    cleanup_response(&response);
    return rc;
}

void run_integrity_check(SSL* ssl, Session* session) {
    integrity_report_t report = {0};
    char home_path[SESSION_PATH_MAX];
    int rc = -1;

    if (ssl == NULL || session == NULL || session->username == NULL) {
        return;
    }

    initialize_session_scopes(session);
    if (snprintf(home_path, sizeof(home_path), "/home/%s", session->username) <= 0 ||
        strlen(home_path) >= sizeof(home_path)) {
        fprintf(stderr, "Integrity check skipped: invalid home path\n");
        return;
    }

    rc = scan_directory_integrity(ssl, session, home_path, &report);
    if (rc != 0 && report.scan_errors == 0 && report.corrupted_files == 0 &&
        report.corrupted_names == 0) {
        fprintf(stderr, "Integrity check could not complete.\n");
        return;
    }

    if (report.corrupted_files > 0 || report.corrupted_names > 0) {
        fprintf(stderr,
                "Integrity warning: %zu corrupted file(s) and %zu corrupted name(s) detected.\n",
                report.corrupted_files, report.corrupted_names);
        return;
    }

    if (report.scan_errors > 0) {
        fprintf(stderr,
                "Integrity check completed with %zu scan issue(s), but no corruption was detected.\n",
                report.scan_errors);
        return;
    }

    printf("Integrity check passed.\n");
}

static int command_pwd(Session* session) {
    if (session == NULL) {
        return -1;
    }

    printf("%s\n", session->cwd);
    return 0;
}

static int command_ls(SSL* ssl, Session* session, const char* path_arg) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* entries = NULL;
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char dir_key[crypto_secretbox_KEYBYTES];

    if (path_arg == NULL) {
        path_arg = ".";
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0 ||
        resolve_directory_name_key(ssl, session, path, dir_key, NULL) != 0) {
        fprintf(stderr, "Failed to prepare encrypted directory path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_path);
    if (perform_request(ssl, GET, "/files", query, session->token, NONE, NULL,
                        0, &response) != 0) {
        fprintf(stderr, "Failed to list directory\n");
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("ls", &response);
        cleanup_response(&response);
        return -1;
    }

    json = cJSON_Parse((char*)response.body);
    entries = json ? cJSON_GetObjectItemCaseSensitive(json, "entries") : NULL;
    if (!cJSON_IsArray(entries)) {
        cJSON_Delete(json);
        cleanup_response(&response);
        return -1;
    }

    cJSON* item = NULL;
    cJSON_ArrayForEach(item, entries) {
        cJSON* name_json = cJSON_GetObjectItemCaseSensitive(item, "name");
        cJSON* type_json = cJSON_GetObjectItemCaseSensitive(item, "object_type");
        cJSON* mode_json = cJSON_GetObjectItemCaseSensitive(item, "mode_bits");
        cJSON* group_id_json = cJSON_GetObjectItemCaseSensitive(item, "group_id");
        char* decrypted_name = NULL;
        char child_path[SESSION_PATH_MAX];

        if (cJSON_IsString(name_json) && name_json->valuestring != NULL &&
            cJSON_IsString(type_json) && type_json->valuestring != NULL &&
            cJSON_IsNumber(mode_json)) {
            decrypted_name =
                decrypt_name_component_hex(dir_key, name_json->valuestring);
            if (decrypted_name == NULL) {
                continue;
            }
            printf("%c %04o %s\n",
                   strcmp(type_json->valuestring, "directory") == 0 ? 'd' : '-',
                   mode_json->valueint, decrypted_name);

            if (strcmp(type_json->valuestring, "directory") == 0 &&
                build_child_path(path, decrypted_name, child_path,
                                 sizeof(child_path)) == 0) {
                if (cJSON_IsNumber(group_id_json)) {
                    char group_name[SESSION_GROUP_NAME_MAX];

                    if (fetch_group_name_by_id(ssl, session, group_id_json->valueint,
                                               group_name, sizeof(group_name)) == 0) {
                        cache_path_scope(session, child_path, group_name);
                    }
                } else {
                    path_scope_info_t inherited = {0};
                    if (lookup_path_scope(session, path, &inherited) == 0) {
                        cache_path_scope(session, child_path,
                                         inherited.has_group ? inherited.group_name
                                                             : NULL);
                    }
                }
            }
            free(decrypted_name);
        }
    }

    cJSON_Delete(json);
    cleanup_response(&response);
    return 0;
}

static int command_cd(SSL* ssl, Session* session, const char* path_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    int rc = -1;

    if (path_arg == NULL) {
        fprintf(stderr, "usage: cd <directory>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid directory path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        fprintf(stderr, "Failed to encrypt directory path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_path);
    if (perform_request(ssl, GET, "/files", query, session->token, NONE, NULL,
                        0, &response) != 0) {
        fprintf(stderr, "Failed to query directory\n");
        return -1;
    }

    if (response.msg->status_code == 200) {
        strncpy(session->cwd, path, sizeof(session->cwd) - 1);
        session->cwd[sizeof(session->cwd) - 1] = '\0';
        rc = 0;
    } else {
        print_response_error("cd", &response);
    }

    cleanup_response(&response);
    return rc;
}

static int command_mkdir(SSL* ssl, Session* session, const char* path_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char json_body[CLIENT_RESPONSE_JSON_MAX];

    if (path_arg == NULL) {
        fprintf(stderr, "usage: mkdir <directory>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid directory path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        fprintf(stderr, "Failed to encrypt directory path\n");
        return -1;
    }

    snprintf(json_body, sizeof(json_body), "{\"dirpath\":\"%s\"}", encrypted_path);
    if (perform_request(ssl, POST, "/directories", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        return -1;
    }

    if (response.msg->status_code != 201) {
        print_response_error("mkdir", &response);
        cleanup_response(&response);
        return -1;
    }

    printf("Created directory %s\n", path);
    cleanup_response(&response);
    return 0;
}

static int command_create(SSL* ssl, Session* session, const char* path_arg,
                          const char* group_name_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char owner_hex[(crypto_box_SEALBYTES +
                    crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char group_hex[(crypto_secretbox_MACBYTES +
                    crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char parent_group_name[SESSION_GROUP_NAME_MAX];
    char json_body[CLIENT_RESPONSE_JSON_MAX];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    char* allocated_file_key = NULL;
    char* wrapped_owner = NULL;
    char* wrapped_group = NULL;
    const char* effective_group_name = group_name_arg;

    if (path_arg == NULL) {
        fprintf(stderr, "usage: create <remote_path> [group_name]\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid file path\n");
        return -1;
    }

    if (effective_group_name == NULL) {
        char parent[SESSION_PATH_MAX];
        char name[SESSION_PATH_MAX];
        int group_id = 0;
        int has_group_id = 0;

        if (split_parent_child(path, parent, sizeof(parent), name, sizeof(name)) == 0 &&
            fetch_group_info_for_path(ssl, session, parent, &group_id,
                                      &has_group_id) == 0 &&
            has_group_id &&
            fetch_group_name_by_id(ssl, session, group_id, parent_group_name,
                                   sizeof(parent_group_name)) == 0) {
            effective_group_name = parent_group_name;
        }
    }

    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        fprintf(stderr, "Failed to encrypt file path\n");
        return -1;
    }

    allocated_file_key = generate_file_key();
    if (allocated_file_key == NULL) {
        return -1;
    }
    memcpy(file_key, allocated_file_key,
           crypto_secretstream_xchacha20poly1305_KEYBYTES);

    wrapped_owner = encrypt_wrapped_user_key(session->user_keys, allocated_file_key);
    if (wrapped_owner == NULL ||
        hex_encode((unsigned char*)wrapped_owner,
                   crypto_box_SEALBYTES +
                       crypto_secretstream_xchacha20poly1305_KEYBYTES,
                   owner_hex, sizeof(owner_hex)) != 0) {
        free(allocated_file_key);
        free(wrapped_owner);
        return -1;
    }

    if (effective_group_name != NULL) {
        if (load_group_key(ssl, session, effective_group_name, group_key) != 0) {
            fprintf(stderr, "Failed to load group key for %s\n", effective_group_name);
            free(allocated_file_key);
            free(wrapped_owner);
            return -1;
        }

        wrapped_group = encrypt_file_group_key(allocated_file_key, (char*)group_key);
        if (wrapped_group == NULL ||
            hex_encode((unsigned char*)wrapped_group,
                       crypto_secretbox_MACBYTES +
                           crypto_secretstream_xchacha20poly1305_KEYBYTES,
                       group_hex, sizeof(group_hex)) != 0) {
            free(allocated_file_key);
            free(wrapped_owner);
            free(wrapped_group);
            return -1;
        }

        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"group_name\":\"%s\","
                 "\"wrapped_fek_owner\":\"%s\",\"wrapped_fek_group\":\"%s\"}",
                 encrypted_path, effective_group_name, owner_hex, group_hex);
    } else {
        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"wrapped_fek_owner\":\"%s\"}",
                 encrypted_path, owner_hex);
    }

    if (perform_request(ssl, POST, "/files", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        free(allocated_file_key);
        free(wrapped_owner);
        free(wrapped_group);
        return -1;
    }

    if (response.msg->status_code != 201) {
        print_response_error("create", &response);
        cleanup_response(&response);
        free(allocated_file_key);
        free(wrapped_owner);
        free(wrapped_group);
        return -1;
    }

    cache_file_key(session, path, file_key);
    if (effective_group_name != NULL) {
        cache_path_scope(session, path, effective_group_name);
    }
    printf("Created file %s\n", path);
    cleanup_response(&response);
    free(allocated_file_key);
    free(wrapped_owner);
    free(wrapped_group);
    return 0;
}

static int command_write(SSL* ssl, Session* session,
                         const char* remote_path_arg, const char* text) {
    client_response_t response = {0};
    char remote_path[SESSION_PATH_MAX];
    char encrypted_remote_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    char* plaintext_path = NULL;
    unsigned char* encrypted_bytes = NULL;
    size_t encrypted_len = 0;
    char* encrypted_path = NULL;
    int rc = -1;

    if (remote_path_arg == NULL || text == NULL) {
        fprintf(stderr, "usage: write <remote_path> <text>\n");
        return -1;
    }
    if (normalize_path(session->cwd, remote_path_arg, remote_path,
                       sizeof(remote_path)) != 0) {
        fprintf(stderr, "Invalid remote file path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, remote_path, encrypted_remote_path,
                             sizeof(encrypted_remote_path)) != 0) {
        fprintf(stderr, "Failed to encrypt remote file path\n");
        return -1;
    }
    if (fetch_file_key(ssl, session, remote_path, file_key) != 0) {
        fprintf(stderr, "Failed to load FEK for %s\n", remote_path);
        return -1;
    }

    if (write_temp_file((const unsigned char*)text, strlen(text),
                        "sfs_write_plain_", &plaintext_path) != 0) {
        fprintf(stderr, "Failed to stage provided text\n");
        return -1;
    }

    encrypted_path = encrypt_file((char*)file_key, plaintext_path);
    if (encrypted_path == NULL ||
        read_file_bytes(encrypted_path, &encrypted_bytes, &encrypted_len) != 0) {
        fprintf(stderr, "Failed to encrypt provided text\n");
        if (plaintext_path != NULL) {
            unlink(plaintext_path);
        }
        free(plaintext_path);
        free(encrypted_path);
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_remote_path);
    if (perform_request(ssl, PUT, "/files/content", query, session->token, STREAM,
                        encrypted_bytes, encrypted_len, &response) != 0) {
        goto cleanup;
    }
    if (response.msg->status_code != 200) {
        print_response_error("write", &response);
        goto cleanup;
    }

    printf("Wrote text to %s\n", remote_path);
    rc = 0;

cleanup:
    cleanup_response(&response);
    free(encrypted_bytes);
    if (plaintext_path != NULL) {
        unlink(plaintext_path);
    }
    if (encrypted_path != NULL) {
        unlink(encrypted_path);
    }
    free(plaintext_path);
    free(encrypted_path);
    return rc;
}

static int command_read(SSL* ssl, Session* session,
                        const char* remote_path_arg) {
    client_response_t response = {0};
    char remote_path[SESSION_PATH_MAX];
    char encrypted_remote_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    char* encrypted_path = NULL;
    char* decrypted_path = NULL;
    unsigned char* plaintext = NULL;
    size_t plaintext_len = 0;
    int rc = -1;

    if (remote_path_arg == NULL) {
        fprintf(stderr, "usage: read <remote_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, remote_path_arg, remote_path,
                       sizeof(remote_path)) != 0) {
        fprintf(stderr, "Invalid remote file path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, remote_path, encrypted_remote_path,
                             sizeof(encrypted_remote_path)) != 0) {
        fprintf(stderr, "Failed to encrypt remote file path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_remote_path);
    if (perform_request(ssl, GET, "/files/contents", query, session->token, NONE,
                        NULL, 0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("read", &response);
        cleanup_response(&response);
        return -1;
    }

    if (resolve_file_key_from_read(ssl, session, remote_path,
                                   response.msg->x_wrapped_fek,
                                   response.msg->x_fek_scope, file_key) != 0) {
        fprintf(stderr, "Failed to resolve FEK for %s\n", remote_path);
        cleanup_response(&response);
        return -1;
    }

    if (write_temp_file(response.body, response.body_len, "sfs_read_enc_",
                        &encrypted_path) != 0) {
        cleanup_response(&response);
        return -1;
    }

    decrypted_path = decrypt_file((char*)file_key, encrypted_path);
    if (decrypted_path == NULL ||
        read_file_bytes(decrypted_path, &plaintext, &plaintext_len) != 0) {
        fprintf(stderr, "Failed to decrypt remote file\n");
        goto cleanup;
    }

    fwrite(plaintext, 1, plaintext_len, stdout);
    if (plaintext_len == 0 || plaintext[plaintext_len - 1] != '\n') {
        printf("\n");
    }

    rc = 0;

cleanup:
    cleanup_response(&response);
    free(plaintext);
    if (encrypted_path != NULL) {
        unlink(encrypted_path);
    }
    if (decrypted_path != NULL) {
        unlink(decrypted_path);
    }
    free(encrypted_path);
    free(decrypted_path);
    return rc;
}

static int command_rm(SSL* ssl, Session* session, const char* path_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char query[HTTP_MAX_QUERY_LEN];

    if (path_arg == NULL) {
        fprintf(stderr, "usage: rm <remote_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid file path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        fprintf(stderr, "Failed to encrypt file path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", encrypted_path);
    if (perform_request(ssl, DELETE, "/files", query, session->token, NONE, NULL,
                        0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("rm", &response);
        cleanup_response(&response);
        return -1;
    }

    printf("Deleted %s\n", path);
    cleanup_response(&response);
    return 0;
}

static int command_mv(SSL* ssl, Session* session, const char* src_arg,
                      const char* dst_arg) {
    client_response_t response = {0};
    char src[SESSION_PATH_MAX];
    char dst[SESSION_PATH_MAX];
    char encrypted_src[SESSION_PATH_MAX * 3];
    char encrypted_dst[SESSION_PATH_MAX * 3];
    char json_body[CLIENT_RESPONSE_JSON_MAX];

    if (src_arg == NULL || dst_arg == NULL) {
        fprintf(stderr, "usage: mv <source_path> <destination_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, src_arg, src, sizeof(src)) != 0 ||
        normalize_path(session->cwd, dst_arg, dst, sizeof(dst)) != 0) {
        fprintf(stderr, "Invalid move path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, src, encrypted_src,
                             sizeof(encrypted_src)) != 0 ||
        encrypt_logical_path(ssl, session, dst, encrypted_dst,
                             sizeof(encrypted_dst)) != 0) {
        fprintf(stderr, "Failed to encrypt move path\n");
        return -1;
    }

    snprintf(json_body, sizeof(json_body),
             "{\"source_filepath\":\"%s\",\"destination_filepath\":\"%s\"}",
             encrypted_src, encrypted_dst);
    if (perform_request(ssl, POST, "/files/move", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("mv", &response);
        cleanup_response(&response);
        return -1;
    }

    printf("Moved %s -> %s\n", src, dst);
    cleanup_response(&response);
    return 0;
}

static int command_chmod(SSL* ssl, Session* session, const char* mode_bits,
                         const char* path_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
    char encrypted_path[SESSION_PATH_MAX * 3];
    char owner_hex[(crypto_box_SEALBYTES +
                    crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char group_hex[(crypto_secretbox_MACBYTES +
                    crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char group_name[SESSION_GROUP_NAME_MAX];
    char json_body[CLIENT_RESPONSE_JSON_MAX];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    char* wrapped_owner = NULL;
    char* wrapped_group = NULL;
    long requested_mode = 0;
    int group_id = 0;
    int has_group_id = 0;

    if (mode_bits == NULL || path_arg == NULL) {
        fprintf(stderr, "usage: chmod <mode_bits> <remote_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid path\n");
        return -1;
    }
    if (encrypt_logical_path(ssl, session, path, encrypted_path,
                             sizeof(encrypted_path)) != 0) {
        fprintf(stderr, "Failed to encrypt path\n");
        return -1;
    }
    if (fetch_file_key(ssl, session, path, file_key) != 0) {
        fprintf(stderr, "Failed to load FEK for %s\n", path);
        return -1;
    }

    errno = 0;
    requested_mode = strtol(mode_bits, NULL, 8);
    if (errno != 0 || requested_mode < 0 || requested_mode > 0777) {
        fprintf(stderr, "Invalid mode bits: %s\n", mode_bits);
        return -1;
    }

    wrapped_owner = encrypt_wrapped_user_key(session->user_keys, (char*)file_key);
    if (wrapped_owner == NULL ||
        hex_encode((unsigned char*)wrapped_owner,
                   crypto_box_SEALBYTES +
                       crypto_secretstream_xchacha20poly1305_KEYBYTES,
                   owner_hex, sizeof(owner_hex)) != 0) {
        free(wrapped_owner);
        return -1;
    }

    if ((requested_mode & 0007) != 0) {
        fprintf(stderr, "Other-scope FEKs are not supported by the client yet\n");
        free(wrapped_owner);
        return -1;
    }

    if ((requested_mode & 0070) != 0) {
        if (fetch_group_info_for_path(ssl, session, path, &group_id,
                                      &has_group_id) != 0 ||
            !has_group_id ||
            fetch_group_name_by_id(ssl, session, group_id, group_name,
                                   sizeof(group_name)) != 0 ||
            load_group_key(ssl, session, group_name, group_key) != 0) {
            fprintf(stderr, "Failed to load group FEK context\n");
            free(wrapped_owner);
            return -1;
        }

        wrapped_group = encrypt_file_group_key((char*)file_key, (char*)group_key);
        if (wrapped_group == NULL ||
            hex_encode((unsigned char*)wrapped_group,
                       crypto_secretbox_MACBYTES +
                           crypto_secretstream_xchacha20poly1305_KEYBYTES,
                       group_hex, sizeof(group_hex)) != 0) {
            free(wrapped_owner);
            free(wrapped_group);
            return -1;
        }

        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"mode_bits\":\"%s\","
                 "\"wrapped_fek_owner\":\"%s\",\"wrapped_fek_group\":\"%s\"}",
                 encrypted_path, mode_bits, owner_hex, group_hex);
    } else {
        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"mode_bits\":\"%s\","
                 "\"wrapped_fek_owner\":\"%s\"}",
                 encrypted_path, mode_bits, owner_hex);
    }

    if (perform_request(ssl, PATCH, "/files/permissions", NULL, session->token,
                        JSON, (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        free(wrapped_owner);
        free(wrapped_group);
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("chmod", &response);
        cleanup_response(&response);
        free(wrapped_owner);
        free(wrapped_group);
        return -1;
    }

    printf("Updated permissions for %s to %s\n", path, mode_bits);
    cleanup_response(&response);
    free(wrapped_owner);
    free(wrapped_group);
    return 0;
}

static int command_group_create(SSL* ssl, Session* session,
                                const char* group_name) {
    client_response_t response = {0};
    unsigned char groups_root_key[crypto_secretbox_KEYBYTES];
    char* groups_component = NULL;
    char* group_component = NULL;
    char groups_root_path[SESSION_PATH_MAX];
    char group_dir_path[SESSION_PATH_MAX];
    char wrapped_hex[(crypto_box_SEALBYTES +
                      crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char json_body[CLIENT_RESPONSE_JSON_MAX];
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    char* allocated_group_key = NULL;
    char* wrapped_group_key = NULL;

    if (group_name == NULL) {
        fprintf(stderr, "usage: group-create <group_name>\n");
        return -1;
    }
    if (derive_groups_root_name_key(groups_root_key) != 0) {
        return -1;
    }
    groups_component = encrypt_name_component_hex(groups_root_key, "groups");
    group_component = encrypt_name_component_hex(groups_root_key, group_name);
    if (groups_component == NULL || group_component == NULL ||
        snprintf(groups_root_path, sizeof(groups_root_path), "/%s",
                 groups_component) < 0 ||
        snprintf(group_dir_path, sizeof(group_dir_path), "/%s/%s",
                 groups_component, group_component) < 0) {
        free(groups_component);
        free(group_component);
        return -1;
    }

    allocated_group_key = generate_group_key();
    if (allocated_group_key == NULL) {
        free(groups_component);
        free(group_component);
        return -1;
    }
    memcpy(group_key, allocated_group_key, crypto_secretbox_KEYBYTES);

    wrapped_group_key =
        encrypt_wrapped_user_key(session->user_keys, allocated_group_key);
    if (wrapped_group_key == NULL ||
        hex_encode((unsigned char*)wrapped_group_key,
                   crypto_box_SEALBYTES +
                       crypto_secretstream_xchacha20poly1305_KEYBYTES,
                   wrapped_hex, sizeof(wrapped_hex)) != 0) {
        free(groups_component);
        free(group_component);
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }

    snprintf(json_body, sizeof(json_body),
             "{\"group_name\":\"%s\",\"wrapped_group_key\":\"%s\","
             "\"groups_root_path\":\"%s\",\"groups_root_name\":\"%s\","
             "\"group_dir_path\":\"%s\",\"group_dir_name\":\"%s\"}",
             group_name, wrapped_hex, groups_root_path, groups_component,
             group_dir_path, group_component);
    if (perform_request(ssl, POST, "/groups", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        free(groups_component);
        free(group_component);
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }
    if (response.msg->status_code != 201) {
        print_response_error("group-create", &response);
        cleanup_response(&response);
        free(groups_component);
        free(group_component);
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }

    cache_group_key(session, group_name, group_key);
    cache_path_scope(session, "/groups", GROUPS_SHARED_SCOPE);
    {
        char logical_group_dir[SESSION_PATH_MAX];
        if (snprintf(logical_group_dir, sizeof(logical_group_dir), "/groups/%s",
                     group_name) > 0 &&
            strlen(logical_group_dir) < sizeof(logical_group_dir)) {
            cache_path_scope(session, logical_group_dir, group_name);
        }
    }
    printf("Created group %s\n", group_name);
    cleanup_response(&response);
    free(groups_component);
    free(group_component);
    free(allocated_group_key);
    free(wrapped_group_key);
    return 0;
}

static int command_group_add(SSL* ssl, Session* session, const char* group_name,
                             const char* username) {
    client_response_t response = {0};
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    unsigned char target_public_key[crypto_box_PUBLICKEYBYTES];
    UserKeys target_user_keys;
    char wrapped_hex[(crypto_box_SEALBYTES +
                      crypto_secretstream_xchacha20poly1305_KEYBYTES) * 2 + 1];
    char json_body[CLIENT_RESPONSE_JSON_MAX];
    char* wrapped_group_key = NULL;

    if (group_name == NULL || username == NULL) {
        fprintf(stderr, "usage: group-add <group_name> <username>\n");
        return -1;
    }
    if (load_group_key(ssl, session, group_name, group_key) != 0) {
        fprintf(stderr, "Failed to load group key for %s\n", group_name);
        return -1;
    }
    if (fetch_user_public_encryption_key(ssl, session, username,
                                         target_public_key) != 0) {
        fprintf(stderr, "Failed to fetch public key for %s\n", username);
        return -1;
    }

    memset(&target_user_keys, 0, sizeof(target_user_keys));
    memcpy(target_user_keys.public_key, target_public_key,
           sizeof(target_public_key));
    wrapped_group_key =
        encrypt_wrapped_user_key(&target_user_keys, (char*)group_key);
    if (wrapped_group_key == NULL ||
        hex_encode((unsigned char*)wrapped_group_key,
                   crypto_box_SEALBYTES +
                       crypto_secretstream_xchacha20poly1305_KEYBYTES,
                   wrapped_hex, sizeof(wrapped_hex)) != 0) {
        free(wrapped_group_key);
        return -1;
    }

    snprintf(json_body, sizeof(json_body),
             "{\"group_name\":\"%s\",\"username\":\"%s\","
             "\"wrapped_group_key\":\"%s\"}",
             group_name, username, wrapped_hex);
    if (perform_request(ssl, POST, "/groups/members", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        free(wrapped_group_key);
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("group-add", &response);
        cleanup_response(&response);
        free(wrapped_group_key);
        return -1;
    }

    printf("Added %s to %s\n", username, group_name);
    cleanup_response(&response);
    free(wrapped_group_key);
    return 0;
}

static int command_group_remove(SSL* ssl, Session* session,
                                const char* group_name, const char* username) {
    client_response_t response = {0};
    char json_body[CLIENT_RESPONSE_JSON_MAX];

    if (group_name == NULL || username == NULL) {
        fprintf(stderr, "usage: group-rm <group_name> <username>\n");
        return -1;
    }

    snprintf(json_body, sizeof(json_body),
             "{\"group_name\":\"%s\",\"username\":\"%s\"}", group_name,
             username);
    if (perform_request(ssl, DELETE, "/groups/members", NULL, session->token,
                        JSON, (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("group-rm", &response);
        cleanup_response(&response);
        return -1;
    }

    printf("Removed %s from %s\n", username, group_name);
    cleanup_response(&response);
    return 0;
}

static int command_group_list(SSL* ssl, Session* session, const char* username) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* groups = NULL;
    char query[HTTP_MAX_QUERY_LEN];

    if (username != NULL) {
        snprintf(query, sizeof(query), "username=%s", username);
    } else {
        query[0] = '\0';
    }

    if (perform_request(ssl, GET, "/groups", query[0] != '\0' ? query : NULL,
                        session->token, NONE, NULL, 0, &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("group-list", &response);
        cleanup_response(&response);
        return -1;
    }

    json = cJSON_Parse((char*)response.body);
    groups = json ? cJSON_GetObjectItemCaseSensitive(json, "groups") : NULL;
    if (!cJSON_IsArray(groups)) {
        cJSON_Delete(json);
        cleanup_response(&response);
        return -1;
    }

    cJSON* item = NULL;
    cJSON_ArrayForEach(item, groups) {
        cJSON* group_id_json = cJSON_GetObjectItemCaseSensitive(item, "group_id");
        cJSON* group_name_json = cJSON_GetObjectItemCaseSensitive(item, "group_name");
        cJSON* owner_json = cJSON_GetObjectItemCaseSensitive(item, "is_owner");
        if (cJSON_IsNumber(group_id_json) && cJSON_IsString(group_name_json) &&
            group_name_json->valuestring != NULL) {
            printf("%d %s%s\n", group_id_json->valueint,
                   group_name_json->valuestring,
                   cJSON_IsBool(owner_json) && cJSON_IsTrue(owner_json)
                       ? " (owner)"
                       : "");
        }
    }

    cJSON_Delete(json);
    cleanup_response(&response);
    return 0;
}

static int command_group_key(SSL* ssl, Session* session, const char* group_name) {
    unsigned char group_key[crypto_secretbox_KEYBYTES];
    char group_key_hex[crypto_secretbox_KEYBYTES * 2 + 1];

    if (group_name == NULL) {
        fprintf(stderr, "usage: group-key <group_name>\n");
        return -1;
    }

    if (load_group_key(ssl, session, group_name, group_key) != 0 ||
        hex_encode(group_key, sizeof(group_key), group_key_hex,
                   sizeof(group_key_hex)) != 0) {
        fprintf(stderr, "Failed to fetch group key\n");
        return -1;
    }

    printf("%s: %s\n", group_name, group_key_hex);
    return 0;
}

static void print_help(void) {
    printf("Commands:\n");
    printf("  pwd\n");
    printf("  ls [path]\n");
    printf("  cd <path>\n");
    printf("  mkdir <path>\n");
    printf("  create <remote_path> [group_name]\n");
    printf("  write <remote_path> <text>\n");
    printf("  read <remote_path>\n");
    printf("  rm <remote_path>\n");
    printf("  mv <source_path> <destination_path>\n");
    printf("  chmod <mode_bits> <remote_path>\n");
    printf("  group-create <group_name>\n");
    printf("  group-add <group_name> <username>\n");
    printf("  group-rm <group_name> <username>\n");
    printf("  group-list [username]\n");
    printf("  group-key <group_name>\n");
    printf("  help\n");
    printf("  logout\n");
}

void cli_loop(SSL* ssl, Session *session){
    char* args[MAX_ARGS];
    char* input = NULL;
    char* raw_input = NULL;

    if (ssl == NULL || session == NULL) {
        return;
    }

    initialize_session_scopes(session);

    while (true) {
        printf("%s:%s$ ", session->username, session->cwd);
        input = get_input();

        if (input == NULL) {
            fprintf(stderr, "Failed to read input\n");
            return;
        }
        if (input[0] == '\0') {
            free(input);
            continue;
        }

        raw_input = strdup(input);
        if (raw_input == NULL) {
            fprintf(stderr, "Failed to process input\n");
            free(input);
            continue;
        }

        str_to_arr(input, args, MAX_ARGS);
        if (args[0] == NULL) {
            free(raw_input);
            free(input);
            continue;
        }

        if (strcmp(args[0], "pwd") == 0) {
            command_pwd(session);
        } else if (strcmp(args[0], "ls") == 0) {
            command_ls(ssl, session, args[1]);
        } else if (strcmp(args[0], "cd") == 0) {
            command_cd(ssl, session, args[1]);
        } else if (strcmp(args[0], "mkdir") == 0) {
            command_mkdir(ssl, session, args[1]);
        } else if (strcmp(args[0], "create") == 0) {
            command_create(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "write") == 0) {
            char* remote_path_arg = NULL;
            char* text = NULL;

            if (parse_write_command_input(raw_input, &remote_path_arg, &text) != 0) {
                fprintf(stderr, "usage: write <remote_path> <text>\n");
            } else {
                command_write(ssl, session, remote_path_arg, text);
            }
        } else if (strcmp(args[0], "read") == 0) {
            command_read(ssl, session, args[1]);
        } else if (strcmp(args[0], "rm") == 0) {
            command_rm(ssl, session, args[1]);
        } else if (strcmp(args[0], "mv") == 0) {
            command_mv(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "chmod") == 0) {
            command_chmod(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "group-create") == 0) {
            command_group_create(ssl, session, args[1]);
        } else if (strcmp(args[0], "group-add") == 0) {
            command_group_add(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "group-rm") == 0) {
            command_group_remove(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "group-list") == 0) {
            command_group_list(ssl, session, args[1]);
        } else if (strcmp(args[0], "group-key") == 0) {
            command_group_key(ssl, session, args[1]);
        } else if (strcmp(args[0], "help") == 0) {
            print_help();
        } else if (strcmp(args[0], "logout") == 0) {
            if (logout(ssl, session) != 0) {
                fprintf(stderr, "Logout request failed\n");
            }
            destroy_session(session);
            free(raw_input);
            free(input);
            break;
        } else {
            printf("unknown command: %s\n", args[0]);
        }

        free(raw_input);
        free(input);
        raw_input = NULL;
    }
}
