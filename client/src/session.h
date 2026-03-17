#ifndef SESSION
#define SESSION

typedef struct{
    int id;
    char username;
} Session;

/**
 * @brief Prompts a login input from the user, creates and returns a session.
 * 
 * @return Session* 
 */
Session* login();

/**
 * @brief Destorys a session, call this at logout.
 * 
 * @param s 
 */
void destroy_session(Session *s);

#endif