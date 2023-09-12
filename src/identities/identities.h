#ifndef identities_H
#define identities_H

#include <stdint.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

#define IDENTITIES_MIN_LEN                                                     \
  2 * UINT8_NUMBER_LEN + 1 + crypto_sign_ed25519_PUBLICKEYBYTES                \
      + crypto_sign_ed25519_SECRETKEYBYTES + 3 * crypto_hash_sha512_BYTES

typedef struct Identity
{
  unsigned int IDENTITIES_LEN;
  unsigned int NONCE_LEN;
  uint8_t reversible_commit_details[2 * crypto_hash_sha512_BYTES];
  uint8_t irreversible_commit_details[crypto_hash_sha512_BYTES];
  uint8_t (*secret_keys)[crypto_sign_ed25519_SECRETKEYBYTES];
  uint8_t (*public_keys)[crypto_sign_ed25519_PUBLICKEYBYTES];
  uint8_t *nonces;
} identity;

identity *new_identity(const unsigned int IDENTITIES_LEN,
                       const unsigned int NONCE_LEN);
void free_identity(identity *id);
int deserialize_identity(identity *id, const size_t ARRAY_LEN,
                         const uint8_t array[ARRAY_LEN]);
#endif
