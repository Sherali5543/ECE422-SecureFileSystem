#ifndef SESSION
#define SESSION
#include "tls.h"
#include "encryption.h"

#define SESSION_PATH_MAX 1024
#define SESSION_GROUP_NAME_MAX 128
#define SESSION_MAX_GROUP_KEYS 64
#define SESSION_MAX_FILE_KEYS 128
#define SESSION_MAX_PATH_SCOPES 256

typedef struct {
    int in_use;
    char group_name[SESSION_GROUP_NAME_MAX];
    unsigned char key[crypto_secretbox_KEYBYTES];
} SessionGroupKey;

typedef struct {
    int in_use;
    char filepath[SESSION_PATH_MAX];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
} SessionFileKey;

typedef struct {
    int in_use;
    char logical_path[SESSION_PATH_MAX];
    int has_group;
    char group_name[SESSION_GROUP_NAME_MAX];
} SessionPathScope;

typedef struct{
    int id;
    char* username;
    char* token;
    char cwd[SESSION_PATH_MAX];
    UserKeys* user_keys;
    SignKeys* sign_keys;
    SessionGroupKey group_keys[SESSION_MAX_GROUP_KEYS];
    SessionFileKey file_keys[SESSION_MAX_FILE_KEYS];
    SessionPathScope path_scopes[SESSION_MAX_PATH_SCOPES];
} Session;

/**
 * @brief Prompts a login input from the user, creates and returns a session.
 * NOTE: Remember to use destory_session() once you are done.
 * 
 * @return Session* 
 */
Session login(SSL* ssl);
int register_account(SSL* ssl);
int logout(SSL* ssl, Session* session);

/**
 * @brief Deallocates memory associated with a session
 * 
 * @param s 
 */
void destroy_session(Session *s);

#endif
