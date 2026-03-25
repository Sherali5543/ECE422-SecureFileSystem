#include "handlers.h"

// Ls/cd
/*
 * Client requests to cd or ls(maybe ls is local)
 *
 *
 */
void get_files(http_message_t* msg, SSL* ssl, http_message_t* response) {}

// creatfile
/*
 * Client sends
 * POST /files HTTP/1.1
 * Content-length: x
 * 
 * POST /files HTTP/1.1
 * Authorization: Bearer <token>
 * Content-type: application/json      // MIME type
 * Content-length: X
 * Connection: [keep-alive|close]
 *
 * {
 *  "filepath": "/home/enc(un)/enc(doc)/enc(a.pdf)"
 * }
 *
 *
 * Server receives
 * Validates token 
 *  - Decode signature
 * Validate access
 *  - mode bits
 *  - owner id 
 *  - group id 
 *  - other
 * Success
 *  - Send file metadata
 *  - Stream file contents
 * Failure
 *  - 403 forbidden
 */
void create_file(http_message_t* msg, SSL* ssl, http_message_t* response) {
  
}
