# Genarete `main` executable from `main.c`
add_executable(test ./test.c)

include_directories(./include/)
include_directories(./libsodium/src/libsodium/include/sodium/)
include_directories(./libsodium/src/libsodium/include/sodium/private/)

# Link `main` program with `hello` library
target_link_libraries (test dcommitt_static_test)
target_compile_options(
    test
    PUBLIC
    -std=c17 
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
    -fsanitize=address
)