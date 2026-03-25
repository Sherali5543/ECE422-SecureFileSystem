#ifndef SERVER_STORAGE_H
#define SERVER_STORAGE_H

#include "http.h"
#include "server_context.h"

int storage_read_file(server_context_t* ctx, const http_message_t* request,
                      http_message_t* response);
int storage_write_file(server_context_t* ctx, const http_message_t* request,
                       http_message_t* response);

#endif
