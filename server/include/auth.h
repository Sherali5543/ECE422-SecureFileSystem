#ifndef SERVER_AUTH_H
#define SERVER_AUTH_H

#include "http.h"
#include "server_context.h"

int auth_handle_login(server_context_t* ctx, const http_message_t* request,
                      http_message_t* response);
int auth_handle_register(server_context_t* ctx, const http_message_t* request,
                         http_message_t* response);
int auth_handle_logout(server_context_t* ctx, const http_message_t* request,
                       http_message_t* response);
int auth_validate_token(server_context_t* ctx, const http_message_t* request);
const server_session_t* auth_session_from_token(server_context_t* ctx,
                                                const char* token);

#endif
