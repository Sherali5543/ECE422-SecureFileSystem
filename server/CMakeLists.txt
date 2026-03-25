# find_package(PkgConfig REQUIRED)
#
# pkg_check_modules(SQLITE REQUIRED sqlite3)

add_executable(server
    src/main.c
    src/encryption.c
    # src/auth.c
    # src/routes.c
    # src/storage.c
)

target_link_libraries(server PRIVATE
  common
#   ${SQLITE_LIBRARIES}
)
