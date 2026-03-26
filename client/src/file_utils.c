#include "file_utils.h"
#include "encryption.h"
#include "http.h"
#include "tls.h"
#include "cjson/cJSON.h"

#include "client.c"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

// youll have to free the metadata when you are done
http_message_t* request_metadata(char* filepath, Session* s){
    http_message_t* msg = init_request();
    msg->method = GET;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/content?path=%s", filepath);
    
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
    char filepath[512];
    snprintf(filepath, sizeof(filepath), 
        "%s/%s", pwd, filename);
    
    http_message_t* metadata = request_metadata(filepath, s);
    // do some checks on metadata before contiuning
    // need to determine the type of decryption we do

    // ask server for file
    http_message_t* msg = init_request();
    msg->method = GET;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/content?path=%s/%s", pwd, filename);

    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);

    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);
    
    // get back request which is the file as a stream

    msg = read_response(s->ssl);
    // decrypt file
    
    free(msg);

}

void write_file(char* pwd, char* filename, Session* s){
    // first check if we like the metadata
    char filepath[512];
    snprintf(filepath, sizeof(filepath), 
        "%s/%s", pwd, filename);
    
    http_message_t* metadata = request_metadata(pwd, s);
    // do some checks on metadata before contiuning
    // need to determine the type of decryption we do

    // ask server for file
    http_message_t* msg = init_request();
    msg->method = GET;

    char request_endpoint[512];
    snprintf(request_endpoint, sizeof(request_endpoint), 
        "/files/content?path=%s/%s", pwd, filename);

    strncpy(msg->path, request_endpoint, HTTP_MAX_PATH_LEN);

    send_request(s->ssl, msg);
    tls_write(s->ssl, NULL, 0);
    destroy_message(msg);
    
    //get back request
    msg = read_response(s->ssl);
    // decrypt file
    
    // create temp file and open it with the contents of the file

    char template[] = "/tmp/sfs_write_XXXXXX";
    int fd = mkstemp(template);

    if (fd == -1) {
        perror("mkstemp");
        return;
    }
    close(fd); 

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vi %s", template);
    system(cmd);

    // send updated file to server
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

    unlink(encrypted_file);

    // send to server
    http_message_t* msg = init_request();
    msg->method = POST;
    strncpy(msg->path, "/files", HTTP_MAX_PATH_LEN);
    msg->content_type = JSON;
    cJSON* json = cJSON_CreateObject();


    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", filepath, filename);
    cJSON_AddStringToObject(json, "path", fullpath);
    cJSON_AddStringToObject(json, "wrapped_fek_owner", wrapped);
    

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