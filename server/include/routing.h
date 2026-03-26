#include "http.h"
#include "tls.h"

http_message_t *handle_request(http_message_t* msg, SSL* ssl);
