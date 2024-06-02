# Genarete `main` executable from `main.c`
add_executable(commit_test ./commit.test.c)
add_executable(shamir_test ./shamir.test.c)
add_executable(crypto_test ./crypto.test.c)
add_executable(merkle_test ./merkle.test.c)

include_directories(./include/)
include_directories(./libsodium/src/libsodium/include/sodium/)
include_directories(./libsodium/src/libsodium/include/sodium/private/)

# Link `main` program with `hello` library
target_link_libraries (commit_test demos_static_test)
target_compile_options(
    commit_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
    # -fsanitize=address
)

target_link_libraries (shamir_test demos_static_test)
target_compile_options(
    shamir_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
    # -fsanitize=address
)

target_link_libraries (crypto_test demos_static_test)
target_compile_options(
    crypto_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
    # -fsanitize=address
)

target_link_libraries (merkle_test demos_static_test)
target_compile_options(
    merkle_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
    # -fsanitize=address
)
