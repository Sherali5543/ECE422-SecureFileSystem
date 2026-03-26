#ifndef FILE_UTILS
#define FILE_UTILS

#include "session.h"

void read_file(char* filepath, char* filename, Session* s);
void write_file(char* filepath, char* filename, Session* s);
void create_file(char* filepath, char* filename, Session* s);
void delete_file(char* filepath, char* filename, Session* s);

#endif
