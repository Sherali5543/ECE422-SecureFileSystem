#include "schema_helper.h"

#include <stdio.h>
#include <stdlib.h>

int run_schema(sqlite3* db, const char* schema_path) {
    FILE* f = fopen(schema_path, "rb");
    if (f == NULL) {
        perror("schema open");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) {
        perror("schema size");
        fclose(f);
        return -1;
    }
    rewind(f);

    char* sql = malloc((size_t)size + 1);
    if (sql == NULL) {
        fclose(f);
        return -1;
    }

    size_t read_bytes = fread(sql, 1, (size_t)size, f);
    if (read_bytes != (size_t)size) {
        perror("schema read");
        fclose(f);
        free(sql);
        return -1;
    }
    sql[size] = '\0';

    fclose(f);

    char* err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(err);
        free(sql);
        return -1;
    }

    free(sql);
    return 0;
}
