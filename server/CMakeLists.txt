# find_package(PkgConfig REQUIRED)
#
# pkg_check_modules(SQLITE REQUIRED sqlite3)

add_executable(server
    src/main.c
    src/routing/routing.c
    # src/auth.c
    # src/routes.c
    # src/storage.c
)

target_link_libraries(server PRIVATE
  common
)

target_include_directories(server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
