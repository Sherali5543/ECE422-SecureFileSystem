#ifndef SESSION
#define SESSION
#include "tls.h"

typedef struct{
    int id;
    char* username;
} Session;

/**
 * @brief Prompts a login input from the user, creates and returns a session.
 * NOTE: Remember to use destory_session() once you are done.
 * 
 * @return Session* 
 */
Session login(SSL* ssl);

/**
 * @brief Deallocates memory associated with a session
 * 
 * @param s 
 */
void destroy_session(Session *s);

#endif
