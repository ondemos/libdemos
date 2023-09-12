#include "../include/dcommitt.h"

#include "../libsodium/src/libsodium/randombytes/randombytes.c"
#include "../libsodium/src/libsodium/sodium/codecs.c"
#include "../libsodium/src/libsodium/sodium/core.c"
#include "../libsodium/src/libsodium/sodium/utils.c"

// SHA512
#include "../libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c"

// Ed25519
#include "../libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c"
#include "../libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
#include "../libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c"
#include "../libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c"
#include "../libsodium/src/libsodium/crypto_verify/verify.c"

// Utils
#include "./utils/utils.c"

// Interfaces
#include "./identities/identities.c"
#include "./proof/proof.c"

// Main functions
#include "./commitment_update.c"
