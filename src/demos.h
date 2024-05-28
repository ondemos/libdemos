#ifndef demos_H
#define demos_H

#include "../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int generate_identities(
    const unsigned int IDENTITIES_LEN,
    uint8_t nonces[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES],
    uint8_t public_keys[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES],
    uint8_t secret_keys[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t commit_details[crypto_auth_hmacsha512_BYTES]);

int commit(uint8_t out[crypto_hash_sha512_BYTES],
           const uint8_t in[crypto_hash_sha512_BYTES],
           const uint8_t details[crypto_auth_hmacsha512_BYTES]);

int generate_proof(
    const unsigned int PROOF_LEN, const unsigned int IDENTITIES_LEN,
    const uint8_t commit[crypto_hash_sha512_BYTES],
    const uint8_t previous_commit[crypto_hash_sha512_BYTES],
    const uint8_t nonces[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES],
    const uint8_t public_keys[IDENTITIES_LEN]
                             [crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t proof[PROOF_LEN]);

#endif
