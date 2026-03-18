#ifndef SESSION
#define SESSION

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
Session login();

/**
 * @brief Deallocates memory associated with a session
 * 
 * @param s 
 */
void destory_session(Session s);

#endif