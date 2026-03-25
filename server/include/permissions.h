#ifndef SERVER_PERMISSIONS_H
#define SERVER_PERMISSIONS_H

#include "http.h"
#include "server_context.h"

int permissions_check(server_context_t* ctx, const http_message_t* request,
                      const char* action);

#endif
