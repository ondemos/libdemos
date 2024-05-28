#ifndef chacha20poly1305_H
#define chacha20poly1305_H

#include <stdint.h>
#include <string.h>

#include "../utils/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

#define ENCRYPTED_LEN(DATA_LEN)                                                \
  crypto_scalarmult_curve25519_BYTES                                           \
      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN                 \
      + crypto_aead_chacha20poly1305_ietf_ABYTES

#define DECRYPTED_LEN(ENCRYPTED_LEN)                                           \
  ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES                  \
      - crypto_aead_chacha20poly1305_ietf_ABYTES

int
encrypt_chachapoly(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
                   const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                   const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                   const unsigned int ADDITIONAL_DATA_LEN,
                   const uint8_t additional_data[ADDITIONAL_DATA_LEN],
                   uint8_t encrypted[ENCRYPTED_LEN(DATA_LEN)]);

int decrypt_chachapoly(
    const unsigned int ENCRYPTED_LEN,
    const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[DECRYPTED_LEN(ENCRYPTED_LEN)]);

#endif
