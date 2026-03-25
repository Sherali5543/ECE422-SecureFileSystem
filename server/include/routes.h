#ifndef SERVER_ROUTES_H
#define SERVER_ROUTES_H

#include "http.h"
#include "server_context.h"

int route_request(server_context_t* ctx, const http_message_t* request,
                  http_message_t* response);

#endif
