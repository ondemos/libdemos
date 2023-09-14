cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Project Name
project(dcommitt VERSION 1.0.0)

add_library(dcommitt SHARED src/dcommitt.c)
add_library(dcommitt_test SHARED src/dcommitt.c)
add_library(dcommitt_static STATIC ./src/dcommitt.c)
add_library(dcommitt_static_test STATIC ./src/dcommitt.c)

include_directories(./libsodium/src/libsodium/include/sodium/)
include_directories(./libsodium/src/libsodium/include/sodium/private/)

target_compile_options(dcommitt PUBLIC -std=c11 -fPIC -flto -fuse-linker-plugin -Ofast -ffp-contract=fast -ffast-math)
target_compile_options(dcommitt_static PUBLIC -std=c17 -fPIC -flto -fwhole-program -Ofast)

target_compile_options(
    dcommitt_test
    PUBLIC
    -std=c17 
    -fPIC
    -flto
    -fwhole-program
    -ggdb
    -g3
    -Og
    -gdwarf-4
)
target_compile_options(
    dcommitt_static_test
    PUBLIC
    -std=c17 
    -fPIC
    -flto
    -fwhole-program
    -ggdb
    -g3
    -Og
    -gdwarf-4
)

add_subdirectory(./__tests__/)
