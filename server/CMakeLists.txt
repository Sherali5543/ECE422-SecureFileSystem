find_package(PkgConfig REQUIRED)

pkg_check_modules(SQLITE REQUIRED sqlite3)

add_executable(server
    src/main.c
    src/encryption.c
    src/server.c
    src/server_context.c
    src/db/db.c
    src/db/schema_helper.c
    src/routing/routing.c
    src/handlers/user_auth.c
    src/handlers/file_crud.c
)

target_link_libraries(server PRIVATE
  common
  ${SQLITE_LIBRARIES}
)

target_include_directories(server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SQLITE_INCLUDE_DIRS}
)

add_executable(seed_user
    src/dev_seed_user.c
)

target_link_libraries(seed_user PRIVATE
  ${SQLITE_LIBRARIES}
  common
)

target_include_directories(seed_user PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SQLITE_INCLUDE_DIRS}
)
