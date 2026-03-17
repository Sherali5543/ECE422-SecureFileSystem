#ifndef CLI_UTILS
#define CLI_UTILS

/**
 * @brief Prompts an input from the user. Returns the users input as a string.
 * 
 * IMPORTANT: you MUST free the input after you are done with it.
 * @return char* 
 */
char* scan();

/**
 * @brief Fills in the array with words from a string.
It will fill in the array till it is full, anything leftover is not allocated to the array.
 * 
 * @param str 
 * @param array 
 * @param size 
 */
void str_to_arr(char* str, char* array[], int size);

#endif