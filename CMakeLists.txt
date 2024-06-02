cmake_minimum_required(VERSION 3.28.1 FATAL_ERROR)

# Project Name
project(demos VERSION 0.2.6)

# set(CMAKE_C_STANDARD 23)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_PREFIX_PATH "/opt/homebrew")
  set(CMAKE_EXE_LINKER_FLAGS "-L/opt/homebrew/lib " CACHE STRING "" FORCE)
  set(CMAKE_C_FLAGS   "-I/opt/homebrew/include " CACHE STRING "" FORCE )
  set(CMAKE_CXX_FLAGS "-I/opt/homebrew/include " CACHE STRING "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE ALL_SOURCE_FILES src/**/*.cpp src/**/*.hpp src/**/*.c src/**/*.h __tests__/**/*.c __tests__/**/*.h)

add_custom_target(
    clangformat
    ALL
    COMMAND ${CMAKE_PREFIX_PATH}/bin/clang-format 
    -style=file
    -i
    ${ALL_SOURCE_FILES}
)

option(SODIUM_DISABLE_TESTS "Disable tests" OFF)
option(SODIUM_MINIMAL "Only compile the minimum set of functions required for the high-level API" OFF)
option(SODIUM_ENABLE_BLOCKING_RANDOM "Enable this switch only if /dev/urandom is totally broken on the target platform" OFF)

add_library(demos SHARED
  src/demos.c
  libsodium/src/libsodium/randombytes/randombytes.c
  libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
	libsodium/src/libsodium/sodium/runtime.c
	libsodium/src/libsodium/sodium/codecs.c
	libsodium/src/libsodium/sodium/core.c
	libsodium/src/libsodium/sodium/utils.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aead_aegis128l.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_common.h
	libsodium/src/libsodium/crypto_aead/aegis256/aead_aegis256.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_soft.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_common.h
	libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
	libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c
	libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
  libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
  libsodium/src/libsodium/crypto_core/softaes/softaes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c
	libsodium/src/libsodium/crypto_verify/verify.c
	libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c
	libsodium/src/libsodium/crypto_generichash/crypto_generichash.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
  libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
	libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
	libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c
  libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c
  libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c
	libsodium/src/libsodium/crypto_kx/crypto_kx.c
	libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
  libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
  libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
  libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
)
add_library(demos_test SHARED 
  src/demos.c
  libsodium/src/libsodium/randombytes/randombytes.c
  libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
	libsodium/src/libsodium/sodium/runtime.c
	libsodium/src/libsodium/sodium/codecs.c
	libsodium/src/libsodium/sodium/core.c
	libsodium/src/libsodium/sodium/utils.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aead_aegis128l.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_common.h
	libsodium/src/libsodium/crypto_aead/aegis256/aead_aegis256.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_soft.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_common.h
	libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
	libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c
	libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
  libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
  libsodium/src/libsodium/crypto_core/softaes/softaes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c
	libsodium/src/libsodium/crypto_verify/verify.c
	libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c
	libsodium/src/libsodium/crypto_generichash/crypto_generichash.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
  libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
	libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
	libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c
  libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c
  libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c
	libsodium/src/libsodium/crypto_kx/crypto_kx.c
	libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
	libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
  libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
  libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
  libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
)
add_library(demos_static STATIC 
  src/demos.c
  libsodium/src/libsodium/randombytes/randombytes.c
  libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
	libsodium/src/libsodium/sodium/runtime.c
	libsodium/src/libsodium/sodium/codecs.c
	libsodium/src/libsodium/sodium/core.c
	libsodium/src/libsodium/sodium/utils.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aead_aegis128l.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_common.h
	libsodium/src/libsodium/crypto_aead/aegis256/aead_aegis256.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_soft.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_common.h
	libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
	libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
	libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c
	libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
  libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
  libsodium/src/libsodium/crypto_core/softaes/softaes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c
	libsodium/src/libsodium/crypto_verify/verify.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c
	libsodium/src/libsodium/crypto_generichash/crypto_generichash.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
  libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
	libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
	libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c
  libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c
  libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c
	libsodium/src/libsodium/crypto_kx/crypto_kx.c
	libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
	libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
  libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
  libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
  libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
)
add_library(demos_static_test STATIC 
  src/demos.c
  libsodium/src/libsodium/randombytes/randombytes.c
  libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
	libsodium/src/libsodium/sodium/runtime.c
	libsodium/src/libsodium/sodium/codecs.c
	libsodium/src/libsodium/sodium/core.c
	libsodium/src/libsodium/sodium/utils.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aead_aegis128l.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_soft.c
	libsodium/src/libsodium/crypto_aead/aegis128l/aegis128l_common.h
	libsodium/src/libsodium/crypto_aead/aegis256/aead_aegis256.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_soft.c
	libsodium/src/libsodium/crypto_aead/aegis256/aegis256_common.h
	libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c
	libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c
	libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
  libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
  libsodium/src/libsodium/crypto_core/softaes/softaes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c
	libsodium/src/libsodium/crypto_verify/verify.c
	libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c
	libsodium/src/libsodium/crypto_generichash/crypto_generichash.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
  libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
	libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
	libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c
  libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c
  libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c
	libsodium/src/libsodium/crypto_kx/crypto_kx.c
	libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
	libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
  libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c
  libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c
  libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c
  libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
)

include_directories(libsodium/src/libsodium/include/sodium/)
include_directories(libsodium/src/libsodium/include/sodium/private/)

target_link_libraries(demos m)
target_link_libraries(demos_static m)
target_link_libraries(demos_static_test m)

set_target_properties(demos PROPERTIES C_STANDARD 99)
target_compile_options(demos PUBLIC -fPIC -Ofast -ffp-contract=fast -ffast-math)
target_compile_options(demos_static PUBLIC -fPIC -Ofast)
target_compile_options(
    demos_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
)
target_compile_options(
    demos_static_test
    PUBLIC
    -fPIC
    -ggdb
    -g3
    -Og
    -gdwarf-4
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        $<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:SODIUM_STATIC>
        $<$<BOOL:${SODIUM_MINIMAL}>:SODIUM_LIBRARY_MINIMAL>
    PRIVATE
        CONFIGURED
        $<$<BOOL:${BUILD_SHARED_LIBS}>:SODIUM_DLL_EXPORT>
        $<$<BOOL:${SODIUM_ENABLE_BLOCKING_RANDOM}>:USE_BLOCKING_RANDOM>
        $<$<BOOL:${SODIUM_MINIMAL}>:MINIMAL>
        $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

add_subdirectory(./__tests__/)
