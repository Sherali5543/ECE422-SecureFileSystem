#ifndef CLI_UTILS
#define CLI_UTILS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include <unistd.h>

#include "session.h"
#include "tls.h"

/**
 * @brief Prompts an input from the user. Returns the users input as a string.
 * 
 * IMPORTANT: you MUST free the input after you are done with it.
 * @return char* 
 */
char* get_input();

/**
 * @brief Fills in the array with words from a string.
It will fill in the array till it is full, anything leftover is not allocated to the array.
 * 
 * @param str 
 * @param array 
 * @param size 
 */
void str_to_arr(char* str, char* array[], int size);

void cli_loop(SSL* ssl, Session *session);
void run_integrity_check(SSL* ssl, Session* session);

/**
 * @brief Enables or disables echo for user input
 * 
 * @param enable 
 */
void setStdinEcho(bool enable);

#endif
