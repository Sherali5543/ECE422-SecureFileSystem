#include "file_utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "encryption.h"
#include "http.h"
#include "tls.h"

<<<<<<< Updated upstream
#include "client.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

=======
>>>>>>> Stashed changes
static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

static int decode_hex_string(const char* hex, unsigned char* out,
                             size_t out_cap, size_t* out_len) {
  size_t hex_len = 0;

  if (!hex || !out || !out_len) {
    return -1;
  }

  hex_len = strlen(hex);
  if ((hex_len % 2) != 0 || (hex_len / 2) > out_cap) {
    return -1;
  }

  for (size_t i = 0; i < hex_len; i += 2) {
    int hi = hex_value(hex[i]);
    int lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i / 2] = (unsigned char)((hi << 4) | lo);
  }

  *out_len = hex_len / 2;
  return 0;
}

static int encode_hex_string(const unsigned char* data, size_t data_len,
                             char* out, size_t out_cap) {
  static const char hex_chars[] = "0123456789abcdef";

  if (!out || out_cap == 0) {
    return -1;
  }
  if ((data_len > 0 && data == NULL) || (data_len * 2 + 1) > out_cap) {
    return -1;
  }

  for (size_t i = 0; i < data_len; i++) {
    out[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex_chars[data[i] & 0x0F];
  }
  out[data_len * 2] = '\0';
  return 0;
}

static int join_logical_path(const char* dir, const char* name, char* out,
                             size_t out_size) {
  int written = 0;

  if (!dir || !name || !out || out_size == 0) {
    return -1;
  }

  if (dir[0] == '\0' || strcmp(dir, "/") == 0) {
    written = snprintf(out, out_size, "/%s", name);
  } else if (dir[strlen(dir) - 1] == '/') {
    written = snprintf(out, out_size, "%s%s", dir, name);
  } else {
    written = snprintf(out, out_size, "%s/%s", dir, name);
  }

  return (written < 0 || (size_t)written >= out_size) ? -1 : 0;
}

static int read_response_body(http_message_t* msg, SSL* ssl, char** out_body) {
  char* body = NULL;

  if (!msg || !ssl || !out_body) {
    return -1;
  }

  body = calloc(msg->content_length + 1, 1);
  if (!body) {
    return -1;
  }

<<<<<<< Updated upstream
    memcpy(msg->auth_token, s->token, sizeof(msg->auth_token));

    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);
    
    //get back request
    msg = read_response(s->ssl);
   
    char* wrapped_key = malloc(4096);

    size_t outlen;
    
    decode_hex_string(msg->x_wrapped_fek,  (unsigned char *) wrapped_key, 4096, &outlen);

    // ACCESS_TYPE at;
    // if (strcmp()){

    // }


    char* file_key = decrypt_wrapped_user_key(s->user_keys, wrapped_key);


    // create temp file and open it with the contents of the file
    char* buffer = calloc(msg->content_length + 1, 1);
    read_message_body(s->ssl, msg, buffer,msg->content_length);

    char template[] = "/tmp/sfs_raw_XXXXXX";
    int fd = mkstemp(template);
    
    write(fd, buffer, msg->content_length);
    close(fd);

    // decrypt file
    char* d_filepath = decrypt_file(file_key, template);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vi %s", d_filepath);
    system(cmd);
    
    free(msg);

}

void write_file(char* pwd, char* filename, Session* s){
    // first check if we like the metadata
    char filepath[512];
    snprintf(filepath, sizeof(filepath), 
        "%s/%s", pwd, filename);
    
    // http_message_t* metadata = request_metadata(pwd, s);
    // // do some checks on metadata before contiuning
    // // need to determine the type of decryption we do
    // char* md_buf = calloc(metadata->content_length + 1, 1);
    // read_message_body(s->ssl, metadata, md_buf,metadata->content_length);

    // cJSON* md_json = cJSON_Parse(md_buf);


    // cJSON* key_json;
    // char* key;
    // if(cJSON_HasObjectItem(md_json, "wrapped_fek_owner")){
    //     key_json = cJSON_GetObjectItem(md_json, "wrapped_fek_owner");
    //     key = key_json->valuestring;
    // } else if (cJSON_HasObjectItem(md_json, "wrapped_fek_group")){
    //     key_json = cJSON_GetObjectItem(md_json, "wrapped_fek_group");
    //     key = key_json->valuestring;
    // } else if (cJSON_HasObjectItem(md_json, "wrapped_fek_other")){
    //     key_json = cJSON_GetObjectItem(md_json, "wrapped_fek_other");
    //     key = key_json->valuestring;
    // } else {
    //     printf("panic!");
    //     return;
    // }

    // ask server for file
    http_message_t* msg = init_request();
    msg->method = GET;
    memcpy(msg->auth_token, s->token, sizeof(msg->auth_token));

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/contents?filepath=%s/%s", pwd, filename);

    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);

    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);
    
    //get back request
    msg = read_response(s->ssl);
   
    char* wrapped_key = malloc(4096);

    size_t outlen;
    
    decode_hex_string(msg->x_wrapped_fek, (unsigned char *) wrapped_key, 4096, &outlen);

    // ACCESS_TYPE at;
    // if (strcmp()){

    // }


    char* file_key = decrypt_wrapped_user_key(s->user_keys, wrapped_key);


    // create temp file and open it with the contents of the file
    char* buffer = calloc(msg->content_length + 1, 1);
    read_message_body(s->ssl, msg, buffer,msg->content_length);

    char template[] = "/tmp/sfs_raw_XXXXXX";
    int fd = mkstemp(template);
    
    write(fd, buffer, msg->content_length);
    close(fd);

    // decrypt file
    char* d_filepath = decrypt_file(file_key, template);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vi %s", d_filepath);
    system(cmd);

    char* e_filepath = encrypt_file(file_key, d_filepath);

    // send updated file to server
    http_message_t* final_msg = init_request();
    final_msg->method = PUT;
    memcpy(final_msg->auth_token, s->token, sizeof(final_msg->auth_token));

    char f_request_endpoint[512];
    snprintf(f_request_endpoint, sizeof(f_request_endpoint), 
        "/files/content?filepath=%s/%s", pwd, filename);

    strncpy(final_msg->path, f_request_endpoint, HTTP_MAX_PATH_LEN);

    fd = open(e_filepath, O_RDONLY);

    struct stat st;

    fstat(fd, &st);

    final_msg->content_type = STREAM;
    final_msg->content_length = (size_t)st.st_size;

    send_request(s->ssl, final_msg);
    
    char buf[1024];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
        break;
        }
        if (n == 0) {
        break;
        }
        if (tls_write(s->ssl, buf, (size_t)n) != n) {
        break;
        }
    }

    destroy_message(final_msg);
}

void create_file(char* filepath, char* filename, Session* s){
    // Defaults perms for the file will only allow owner to access it
    char template[] = "/tmp/sfs_create_XXXXXX";
    int fd = mkstemp(template);

    if (fd == -1) {
        perror("mkstemp");
        return;
    }
    close(fd); 

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vi %s", template);
    system(cmd);

    // encrypt the file
    char *file_key = NULL;
    char *encrypted_file = NULL;
    file_key = generate_file_key();
    encrypted_file = encrypt_file(file_key, template);
    unlink(template);

    // wrap file key with user key
    char* wrapped = NULL;
    wrapped = encrypt_wrapped_user_key(s->user_keys, file_key);

    char w_enc[4096];
    encode_hex_string((const unsigned char *) wrapped, (size_t) WRAPPED_USER_KEY_SIZE, w_enc, sizeof(w_enc));

    // char* hash = generate_file_hash(encrypted_file);

    // char* signature

    unlink(encrypted_file);

    // send to server
    http_message_t* msg = init_request();
    msg->method = POST;
    memcpy(msg->auth_token, s->token, sizeof(msg->auth_token));
    strncpy(msg->path, "/files", HTTP_MAX_PATH_LEN);
    msg->content_type = JSON;
    cJSON* json = cJSON_CreateObject();


    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", filepath, filename);
    cJSON_AddStringToObject(json, "filepath", fullpath);
    cJSON_AddStringToObject(json, "wrapped_fek_owner", w_enc);    

    char* body = cJSON_PrintUnformatted(json);
    msg->content_length = strlen(body);

    send_request(s->ssl, msg);
    tls_write(s->ssl, body, strlen(body));
    destroy_message(msg);
=======
  if (msg->content_length > 0 &&
      read_message_body(ssl, msg, body, msg->content_length) !=
          (ssize_t)msg->content_length) {
>>>>>>> Stashed changes
    free(body);
    return -1;
  }

  *out_body = body;
  return 0;
}

static void print_error_response(const char* action, http_message_t* response,
                                 char* body) {
  if (!response) {
    fprintf(stderr, "%s failed: no response\n", action);
    return;
  }

  if (body && body[0] != '\0') {
    fprintf(stderr, "%s failed: HTTP %d %s: %s\n", action,
            response->status_code, response->reason, body);
  } else {
    fprintf(stderr, "%s failed: HTTP %d %s\n", action, response->status_code,
            response->reason);
  }
}

static http_message_t* send_request_with_body(Session* s, http_method_t method,
                                              const char* path,
                                              const char* query,
                                              http_content_type_t content_type,
                                              const void* body,
                                              size_t body_len) {
  http_message_t* msg = NULL;
  http_message_t* response = NULL;

  if (!s || !s->ssl || !s->token || !path) {
    return NULL;
  }

  msg = init_request();
  if (!msg) {
    return NULL;
  }

  msg->method = method;
  msg->content_type = content_type;
  msg->content_length = body_len;
  strncpy(msg->path, path, sizeof(msg->path) - 1);
  msg->path[sizeof(msg->path) - 1] = '\0';
  if (query) {
    strncpy(msg->query, query, sizeof(msg->query) - 1);
    msg->query[sizeof(msg->query) - 1] = '\0';
  }
  strncpy(msg->auth_token, s->token, sizeof(msg->auth_token) - 1);
  msg->auth_token[sizeof(msg->auth_token) - 1] = '\0';

  send_request(s->ssl, msg);
  if (body_len > 0 && tls_write(s->ssl, (void*)body, body_len) !=
                          (ssize_t)body_len) {
    destroy_message(msg);
    return NULL;
  }
  destroy_message(msg);

  response = read_response(s->ssl);
  return response;
}

static int slurp_file(const char* filepath, unsigned char** out_buf,
                      size_t* out_len) {
  struct stat st;
  unsigned char* buf = NULL;
  int fd = -1;

  if (!filepath || !out_buf || !out_len) {
    return -1;
  }

  if (stat(filepath, &st) != 0 || st.st_size < 0) {
    return -1;
  }

  buf = calloc((size_t)st.st_size + 1, 1);
  if (buf == NULL) {
    return -1;
  }

  fd = open(filepath, O_RDONLY);
  if (fd < 0) {
    free(buf);
    return -1;
  }

  if (st.st_size > 0 &&
      read(fd, buf, (size_t)st.st_size) != (ssize_t)st.st_size) {
    close(fd);
    free(buf);
    return -1;
  }

  close(fd);
  *out_buf = buf;
  *out_len = (size_t)st.st_size;
  return 0;
}

static int upload_encrypted_file(Session* s, const char* logical_path,
                                 const char* encrypted_filepath) {
  unsigned char* encrypted_bytes = NULL;
  size_t encrypted_len = 0;
  http_message_t* response = NULL;
  char query[HTTP_MAX_QUERY_LEN];
  char* body = NULL;
  int rc = -1;

  if (!s || !logical_path || !encrypted_filepath) {
    return -1;
  }

  if (snprintf(query, sizeof(query), "filepath=%s", logical_path) < 0 ||
      strlen(query) >= sizeof(query)) {
    return -1;
  }

  if (slurp_file(encrypted_filepath, &encrypted_bytes, &encrypted_len) != 0) {
    return -1;
  }

  response = send_request_with_body(s, PUT, "/files/content", query, STREAM,
                                    encrypted_bytes, encrypted_len);
  if (!response) {
    goto cleanup;
  }

  if (read_response_body(response, s->ssl, &body) != 0) {
    goto cleanup;
  }

  if (response->status_code != 200) {
    print_error_response("write file", response, body);
    goto cleanup;
  }

  rc = 0;

cleanup:
  free(encrypted_bytes);
  free(body);
  destroy_message(response);
  return rc;
}

static int download_encrypted_file(Session* s, const char* logical_path,
                                   char** out_encrypted_path,
                                   char** out_file_key) {
  http_message_t* response = NULL;
  unsigned char wrapped_key[HTTP_MAX_HEADER_VALUE];
  size_t wrapped_key_len = 0;
  char query[HTTP_MAX_QUERY_LEN];
  char* encrypted_path = NULL;
  char* file_key = NULL;
  char template[] = "/tmp/sfs_raw_XXXXXX";
  int fd = -1;
  char* body = NULL;
  int rc = -1;

  if (!s || !logical_path || !out_encrypted_path || !out_file_key) {
    return -1;
  }

  *out_encrypted_path = NULL;
  *out_file_key = NULL;

  if (snprintf(query, sizeof(query), "filepath=%s", logical_path) < 0 ||
      strlen(query) >= sizeof(query)) {
    return -1;
  }

  response = send_request_with_body(s, GET, "/files/contents", query, NONE,
                                    NULL, 0);
  if (!response) {
    return -1;
  }

  if (response->status_code != 200) {
    if (read_response_body(response, s->ssl, &body) == 0) {
      print_error_response("read file", response, body);
    }
    goto cleanup;
  }

  if (strcmp(response->x_fek_scope, "owner") != 0) {
    fprintf(stderr,
            "read file failed: unsupported FEK scope '%s' for client decrypt\n",
            response->x_fek_scope);
    goto cleanup;
  }

  if (decode_hex_string(response->x_wrapped_fek, wrapped_key,
                        sizeof(wrapped_key), &wrapped_key_len) != 0) {
    fprintf(stderr, "read file failed: invalid wrapped FEK\n");
    goto cleanup;
  }

  file_key = decrypt_wrapped_user_key(s->user_keys, (char*)wrapped_key);
  if (!file_key) {
    fprintf(stderr, "read file failed: unable to unwrap FEK\n");
    goto cleanup;
  }

  fd = mkstemp(template);
  if (fd < 0) {
    goto cleanup;
  }

  if (response->content_length > 0) {
    unsigned char* encrypted_bytes = calloc(response->content_length + 1, 1);
    if (!encrypted_bytes) {
      goto cleanup;
    }

    if (read_message_body(s->ssl, response, encrypted_bytes,
                          response->content_length) !=
        (ssize_t)response->content_length) {
      free(encrypted_bytes);
      goto cleanup;
    }

    if (write(fd, encrypted_bytes, response->content_length) !=
        (ssize_t)response->content_length) {
      free(encrypted_bytes);
      goto cleanup;
    }

    free(encrypted_bytes);
  }

  close(fd);
  fd = -1;
  encrypted_path = strdup(template);
  if (!encrypted_path) {
    goto cleanup;
  }

  *out_encrypted_path = encrypted_path;
  *out_file_key = file_key;
  rc = 0;

cleanup:
  if (fd >= 0) {
    close(fd);
    unlink(template);
  }
  if (rc != 0) {
    free(file_key);
    free(encrypted_path);
  }
  free(body);
  destroy_message(response);
  return rc;
}

void read_file(char* pwd, char* filename, Session* s) {
  char logical_path[512];
  char* encrypted_path = NULL;
  char* decrypted_path = NULL;
  char* file_key = NULL;
  char cmd[512];

  if (join_logical_path(pwd, filename, logical_path, sizeof(logical_path)) !=
      0) {
    fprintf(stderr, "read file failed: invalid path\n");
    return;
  }

  if (download_encrypted_file(s, logical_path, &encrypted_path, &file_key) !=
      0) {
    return;
  }

  decrypted_path = decrypt_file(file_key, encrypted_path);
  if (!decrypted_path) {
    fprintf(stderr, "read file failed: unable to decrypt file\n");
    goto cleanup;
  }

  snprintf(cmd, sizeof(cmd), "vi -R %s", decrypted_path);
  system(cmd);

cleanup:
  if (decrypted_path) {
    unlink(decrypted_path);
    free(decrypted_path);
  }
  if (encrypted_path) {
    unlink(encrypted_path);
    free(encrypted_path);
  }
  free(file_key);
}

void write_file(char* pwd, char* filename, Session* s) {
  char logical_path[512];
  char* encrypted_path = NULL;
  char* decrypted_path = NULL;
  char* file_key = NULL;
  char* updated_encrypted_path = NULL;
  char cmd[512];

  if (join_logical_path(pwd, filename, logical_path, sizeof(logical_path)) !=
      0) {
    fprintf(stderr, "write file failed: invalid path\n");
    return;
  }

  if (download_encrypted_file(s, logical_path, &encrypted_path, &file_key) !=
      0) {
    return;
  }

  decrypted_path = decrypt_file(file_key, encrypted_path);
  if (!decrypted_path) {
    fprintf(stderr, "write file failed: unable to decrypt file\n");
    goto cleanup;
  }

  snprintf(cmd, sizeof(cmd), "vi %s", decrypted_path);
  system(cmd);

  updated_encrypted_path = encrypt_file(file_key, decrypted_path);
  if (!updated_encrypted_path) {
    fprintf(stderr, "write file failed: unable to encrypt updated file\n");
    goto cleanup;
  }

  if (upload_encrypted_file(s, logical_path, updated_encrypted_path) != 0) {
    goto cleanup;
  }

cleanup:
  if (updated_encrypted_path) {
    unlink(updated_encrypted_path);
    free(updated_encrypted_path);
  }
  if (decrypted_path) {
    unlink(decrypted_path);
    free(decrypted_path);
  }
  if (encrypted_path) {
    unlink(encrypted_path);
    free(encrypted_path);
  }
  free(file_key);
}

void create_file(char* filepath, char* filename, Session* s) {
  char template[] = "/tmp/sfs_create_XXXXXX";
  char logical_path[512];
  char* file_key = NULL;
  char* encrypted_file = NULL;
  char* wrapped = NULL;
  http_message_t* response = NULL;
  cJSON* json = NULL;
  char* request_body = NULL;
  char* response_body = NULL;
  char wrapped_owner_hex[HTTP_MAX_HEADER_VALUE];
  int fd = -1;
  char cmd[512];

  if (join_logical_path(filepath, filename, logical_path, sizeof(logical_path)) !=
      0) {
    fprintf(stderr, "create file failed: invalid path\n");
    return;
  }

  fd = mkstemp(template);
  if (fd < 0) {
    perror("mkstemp");
    return;
  }
  close(fd);

  snprintf(cmd, sizeof(cmd), "vi %s", template);
  system(cmd);

  file_key = generate_file_key();
  encrypted_file = encrypt_file(file_key, template);
  wrapped = encrypt_wrapped_user_key(s->user_keys, file_key);
  unlink(template);

  if (!file_key || !encrypted_file || !wrapped ||
      encode_hex_string((const unsigned char*)wrapped,
                        (size_t)WRAPPED_USER_KEY_SIZE, wrapped_owner_hex,
                        sizeof(wrapped_owner_hex)) != 0) {
    fprintf(stderr, "create file failed: unable to prepare encrypted file\n");
    goto cleanup;
  }

  json = cJSON_CreateObject();
  if (!json) {
    goto cleanup;
  }
  cJSON_AddStringToObject(json, "filepath", logical_path);
  cJSON_AddStringToObject(json, "wrapped_fek_owner", wrapped_owner_hex);
  request_body = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  json = NULL;
  if (!request_body) {
    goto cleanup;
  }

  response = send_request_with_body(s, POST, "/files", NULL, JSON,
                                    request_body, strlen(request_body));
  if (!response) {
    fprintf(stderr, "create file failed: no response\n");
    goto cleanup;
  }

  if (read_response_body(response, s->ssl, &response_body) != 0) {
    goto cleanup;
  }

  if (response->status_code != 201) {
    print_error_response("create file", response, response_body);
    goto cleanup;
  }

  destroy_message(response);
  response = NULL;
  free(response_body);
  response_body = NULL;

  if (upload_encrypted_file(s, logical_path, encrypted_file) != 0) {
    goto cleanup;
  }

cleanup:
  if (fd >= 0) {
    unlink(template);
  }
  if (response) {
    destroy_message(response);
  }
  if (json) {
    cJSON_Delete(json);
  }
  free(request_body);
  free(response_body);
  free(wrapped);
  free(file_key);
  if (encrypted_file) {
    unlink(encrypted_file);
    free(encrypted_file);
  }
}

void delete_file(char* filepath, char* filename, Session* s) {
  char logical_path[512];
  char query[HTTP_MAX_QUERY_LEN];
  http_message_t* response = NULL;
  char* body = NULL;

  if (join_logical_path(filepath, filename, logical_path, sizeof(logical_path)) !=
      0) {
    fprintf(stderr, "delete file failed: invalid path\n");
    return;
  }

  if (snprintf(query, sizeof(query), "filepath=%s", logical_path) < 0 ||
      strlen(query) >= sizeof(query)) {
    fprintf(stderr, "delete file failed: invalid query\n");
    return;
  }

  response = send_request_with_body(s, DELETE, "/files", query, NONE, NULL, 0);
  if (!response) {
    fprintf(stderr, "delete file failed: no response\n");
    return;
  }

  if (read_response_body(response, s->ssl, &body) != 0) {
    destroy_message(response);
    return;
  }

  if (response->status_code != 200) {
    print_error_response("delete file", response, body);
  }

  free(body);
  destroy_message(response);
}
