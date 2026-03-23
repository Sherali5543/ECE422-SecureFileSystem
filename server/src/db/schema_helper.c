#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

void run_schema(sqlite3 *db, const char *schema_path) {
    FILE *f = fopen(schema_path, "rb");
    if (!f) {
        perror("schema open");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *sql = malloc(size + 1);
    fread(sql, 1, size, f);
    sql[size] = '\0';

    fclose(f);

    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(err);
        exit(1);
    }

    free(sql);
}
