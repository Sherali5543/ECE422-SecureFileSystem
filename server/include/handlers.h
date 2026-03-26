#ifndef HANDLERS_H
#define HANDLERS_H
#include "http.h"
#include "server_context.h"
#include "tls.h"

void create_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx);
void read_file(http_message_t* msg, SSL* ssl, http_message_t* response,
               server_context_t* ctx);
void write_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                server_context_t* ctx);
void delete_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx);
void create_group(http_message_t* msg, SSL* ssl, http_message_t* response,
                  server_context_t* ctx);
void add_group_member(http_message_t* msg, SSL* ssl, http_message_t* response,
                      server_context_t* ctx);
void remove_group_member(http_message_t* msg, SSL* ssl,
                         http_message_t* response, server_context_t* ctx);
void list_user_groups(http_message_t* msg, SSL* ssl, http_message_t* response,
                      server_context_t* ctx);
void get_files(http_message_t* msg, SSL* ssl, http_message_t* response);
#endif
