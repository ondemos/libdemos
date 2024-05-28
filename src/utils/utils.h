#ifndef utils_H
#define utils_H

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "./uint256.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../libsodium/src/libsodium/include/sodium/utils.h"

#define UINT8_NUMBER_LEN 4
#define UINT8_BIGINT_LEN 8

int calculate_proof_len(const unsigned int IDENTITIES_LEN,
                        const unsigned int IDENTITY_INDEX_USED);

void items_indexes_in_array(
    const size_t ARRAY_LEN, const size_t ITEMS_ARRAY_LEN,
    const uint8_t array[ARRAY_LEN][crypto_hash_sha512_BYTES],
    const uint8_t items[ITEMS_ARRAY_LEN][crypto_hash_sha512_BYTES],
    int32_t indexes[ITEMS_ARRAY_LEN]);

int uint8_array_to_number(const uint8_t array[UINT8_NUMBER_LEN]);

void number_to_uint8_array(const unsigned long number,
                           uint8_t array[UINT8_NUMBER_LEN]);

int random_number_in_range(const int MIN, const int MAX);

int sha512(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
           uint8_t hash[crypto_hash_sha512_BYTES]);

int argon2(const unsigned int MNEMONIC_LEN,
           uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
           const char mnemonic[MNEMONIC_LEN],
           const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES]);

void
calculate_nonce(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]);

int keypair(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
            uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

int keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                      uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                      const uint8_t seed[crypto_sign_ed25519_SEEDBYTES]);

int keypair_from_secret_key(
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

int sign(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
         const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
         uint8_t signature[crypto_sign_ed25519_BYTES]);

int verify(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
           const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
           const uint8_t signature[crypto_sign_ed25519_BYTES]);

#endif
