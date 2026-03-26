#include "http.h"
#include "tls.h"
#include "db.h"

http_message_t *handle_request(http_message_t* msg, SSL* ssl, server_context_t *ctx);
