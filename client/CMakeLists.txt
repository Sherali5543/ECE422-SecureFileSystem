add_executable(client
    src/main.c
    src/cli.c
    src/session.c
)

target_link_libraries(client PRIVATE common)
