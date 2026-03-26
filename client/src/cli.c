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

typedef struct {
    http_message_t* msg;
    unsigned char* body;
    size_t body_len;
} client_response_t;

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

static int write_file_bytes(const char* path, const unsigned char* buf,
                            size_t len) {
    int fd = -1;
    size_t total = 0;

    if (path == NULL || (buf == NULL && len > 0)) {
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) {
            perror("write");
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }

    close(fd);
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

static int fetch_group_info_for_path(SSL* ssl, Session* session,
                                     const char* path, int* out_group_id,
                                     int* out_has_group_id) {
    client_response_t response = {0};
    cJSON* json = NULL;
    cJSON* entries_json = NULL;
    char parent[SESSION_PATH_MAX];
    char name[SESSION_PATH_MAX];
    char query[HTTP_MAX_QUERY_LEN];
    int rc = -1;

    if (ssl == NULL || session == NULL || path == NULL || out_group_id == NULL ||
        out_has_group_id == NULL) {
        return -1;
    }

    *out_group_id = 0;
    *out_has_group_id = 0;

    if (split_parent_child(path, parent, sizeof(parent), name, sizeof(name)) != 0) {
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", parent);
    if (perform_request(ssl, GET, "/files", query, session->token, NONE, NULL, 0,
                        &response) != 0) {
        return -1;
    }
    if (response.msg->status_code != 200) {
        print_response_error("list parent directory", &response);
        goto cleanup;
    }

    json = cJSON_Parse((char*)response.body);
    if (json == NULL) {
        goto cleanup;
    }

    entries_json = cJSON_GetObjectItemCaseSensitive(json, "entries");
    if (!cJSON_IsArray(entries_json)) {
        goto cleanup;
    }

    cJSON* item = NULL;
    cJSON_ArrayForEach(item, entries_json) {
        cJSON* path_json = cJSON_GetObjectItemCaseSensitive(item, "path");
        cJSON* group_id_json = cJSON_GetObjectItemCaseSensitive(item, "group_id");

        if (!cJSON_IsString(path_json) || path_json->valuestring == NULL) {
            continue;
        }
        if (strcmp(path_json->valuestring, path) != 0) {
            continue;
        }

        if (cJSON_IsNumber(group_id_json)) {
            *out_group_id = group_id_json->valueint;
            *out_has_group_id = 1;
        }
        rc = 0;
        break;
    }

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
    char query[HTTP_MAX_QUERY_LEN];
    int rc = -1;

    if (ssl == NULL || session == NULL || filepath == NULL || out_key == NULL) {
        return -1;
    }

    if (get_cached_file_key(session, filepath, out_key) == 0) {
        return 0;
    }

    snprintf(query, sizeof(query), "filepath=%s", filepath);
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
    char query[HTTP_MAX_QUERY_LEN];

    if (path_arg == NULL) {
        path_arg = ".";
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", path);
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

        if (cJSON_IsString(name_json) && name_json->valuestring != NULL &&
            cJSON_IsString(type_json) && type_json->valuestring != NULL &&
            cJSON_IsNumber(mode_json)) {
            printf("%c %04o %s\n",
                   strcmp(type_json->valuestring, "directory") == 0 ? 'd' : '-',
                   mode_json->valueint, name_json->valuestring);
        }
    }

    cJSON_Delete(json);
    cleanup_response(&response);
    return 0;
}

static int command_cd(SSL* ssl, Session* session, const char* path_arg) {
    client_response_t response = {0};
    char path[SESSION_PATH_MAX];
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

    snprintf(query, sizeof(query), "filepath=%s", path);
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
    char json_body[CLIENT_RESPONSE_JSON_MAX];

    if (path_arg == NULL) {
        fprintf(stderr, "usage: mkdir <directory>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid directory path\n");
        return -1;
    }

    snprintf(json_body, sizeof(json_body), "{\"dirpath\":\"%s\"}", path);
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
                 path, effective_group_name, owner_hex, group_hex);
    } else {
        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"wrapped_fek_owner\":\"%s\"}",
                 path, owner_hex);
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
    printf("Created file %s\n", path);
    cleanup_response(&response);
    free(allocated_file_key);
    free(wrapped_owner);
    free(wrapped_group);
    return 0;
}

static int command_write(SSL* ssl, Session* session, const char* local_path,
                         const char* remote_path_arg) {
    client_response_t response = {0};
    char remote_path[SESSION_PATH_MAX];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char* encrypted_bytes = NULL;
    size_t encrypted_len = 0;
    char* encrypted_path = NULL;
    int rc = -1;

    if (local_path == NULL || remote_path_arg == NULL) {
        fprintf(stderr, "usage: write <local_path> <remote_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, remote_path_arg, remote_path,
                       sizeof(remote_path)) != 0) {
        fprintf(stderr, "Invalid remote file path\n");
        return -1;
    }
    if (fetch_file_key(ssl, session, remote_path, file_key) != 0) {
        fprintf(stderr, "Failed to load FEK for %s\n", remote_path);
        return -1;
    }

    encrypted_path = encrypt_file((char*)file_key, (char*)local_path);
    if (encrypted_path == NULL ||
        read_file_bytes(encrypted_path, &encrypted_bytes, &encrypted_len) != 0) {
        fprintf(stderr, "Failed to encrypt local file\n");
        free(encrypted_path);
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", remote_path);
    if (perform_request(ssl, PUT, "/files/content", query, session->token, STREAM,
                        encrypted_bytes, encrypted_len, &response) != 0) {
        goto cleanup;
    }
    if (response.msg->status_code != 200) {
        print_response_error("write", &response);
        goto cleanup;
    }

    printf("Wrote %s -> %s\n", local_path, remote_path);
    rc = 0;

cleanup:
    cleanup_response(&response);
    free(encrypted_bytes);
    if (encrypted_path != NULL) {
        unlink(encrypted_path);
    }
    free(encrypted_path);
    return rc;
}

static int command_read(SSL* ssl, Session* session, const char* remote_path_arg,
                        const char* output_path) {
    client_response_t response = {0};
    char remote_path[SESSION_PATH_MAX];
    char query[HTTP_MAX_QUERY_LEN];
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    char* encrypted_path = NULL;
    char* decrypted_path = NULL;
    unsigned char* plaintext = NULL;
    size_t plaintext_len = 0;
    int rc = -1;

    if (remote_path_arg == NULL) {
        fprintf(stderr, "usage: read <remote_path> [output_path]\n");
        return -1;
    }
    if (normalize_path(session->cwd, remote_path_arg, remote_path,
                       sizeof(remote_path)) != 0) {
        fprintf(stderr, "Invalid remote file path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", remote_path);
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

    if (output_path != NULL) {
        if (write_file_bytes(output_path, plaintext, plaintext_len) != 0) {
            goto cleanup;
        }
        printf("Read %s -> %s\n", remote_path, output_path);
    } else {
        fwrite(plaintext, 1, plaintext_len, stdout);
        if (plaintext_len == 0 || plaintext[plaintext_len - 1] != '\n') {
            printf("\n");
        }
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
    char query[HTTP_MAX_QUERY_LEN];

    if (path_arg == NULL) {
        fprintf(stderr, "usage: rm <remote_path>\n");
        return -1;
    }
    if (normalize_path(session->cwd, path_arg, path, sizeof(path)) != 0) {
        fprintf(stderr, "Invalid file path\n");
        return -1;
    }

    snprintf(query, sizeof(query), "filepath=%s", path);
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

    snprintf(json_body, sizeof(json_body),
             "{\"source_filepath\":\"%s\",\"destination_filepath\":\"%s\"}",
             src, dst);
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
                 path, mode_bits, owner_hex, group_hex);
    } else {
        snprintf(json_body, sizeof(json_body),
                 "{\"filepath\":\"%s\",\"mode_bits\":\"%s\","
                 "\"wrapped_fek_owner\":\"%s\"}",
                 path, mode_bits, owner_hex);
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

    allocated_group_key = generate_group_key();
    if (allocated_group_key == NULL) {
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
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }

    snprintf(json_body, sizeof(json_body),
             "{\"group_name\":\"%s\",\"wrapped_group_key\":\"%s\"}",
             group_name, wrapped_hex);
    if (perform_request(ssl, POST, "/groups", NULL, session->token, JSON,
                        (unsigned char*)json_body, strlen(json_body),
                        &response) != 0) {
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }
    if (response.msg->status_code != 201) {
        print_response_error("group-create", &response);
        cleanup_response(&response);
        free(allocated_group_key);
        free(wrapped_group_key);
        return -1;
    }

    cache_group_key(session, group_name, group_key);
    printf("Created group %s\n", group_name);
    cleanup_response(&response);
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
    printf("  write <local_path> <remote_path>\n");
    printf("  read <remote_path> [output_path]\n");
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

    if (ssl == NULL || session == NULL) {
        return;
    }

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

        str_to_arr(input, args, MAX_ARGS);
        if (args[0] == NULL) {
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
            command_write(ssl, session, args[1], args[2]);
        } else if (strcmp(args[0], "read") == 0) {
            command_read(ssl, session, args[1], args[2]);
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
            free(input);
            break;
        } else {
            printf("unknown command: %s\n", args[0]);
        }

        free(input);
    }
}
