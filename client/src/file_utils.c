#include "file_utils.h"
#include "encryption.h"
#include "http.h"
#include "tls.h"
#include "cjson/cJSON.h"

#include "client.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

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

typedef enum ACCESS_TYPE {
    OWNER,
    GROUP,
    OTHER
} ACCESS_TYPE;

// youll have to free the metadata when you are done
http_message_t* request_metadata(char* filepath, Session* s){
    http_message_t* msg = init_request();
    msg->method = GET;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/path=%s", filepath);
    
    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);
    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);

    // get the response
    msg = read_response(s->ssl);

    return msg;
}

void read_file(char* pwd, char* filename, Session* s){
    // first check if we like the metadata
    http_message_t* msg = init_request();
    msg->method = GET;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/contents?filepath=%s/%s", pwd, filename);

    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);

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
    free(body);

    msg = read_response(s->ssl);
    free(msg);

    // just need to read call back
}

void delete_file(char* filepath, char* filename, Session* s){
    http_message_t* msg = init_request();
    msg->method = DELETE;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files?path=%s/%s", filepath, filename);

    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);

    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);
    
    //get back request
    msg = read_response(s->ssl);
}