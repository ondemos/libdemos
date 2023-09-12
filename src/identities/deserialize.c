#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "./identities.h"

#include "../utils/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int
deserialize_identity(identity *id, const size_t ARRAY_LEN,
                     const uint8_t array[ARRAY_LEN])
{
  // condition for when we know
  if (ARRAY_LEN < IDENTITIES_MIN_LEN) return -1;

  uint8_t *uint8NumberArray = malloc(sizeof(uint8_t[UINT8_NUMBER_LEN]));

  memcpy(uint8NumberArray, &array[0], UINT8_NUMBER_LEN);
  id->IDENTITIES_LEN = uint8_array_to_number(uint8NumberArray);

  memcpy(uint8NumberArray, &array[UINT8_NUMBER_LEN], UINT8_NUMBER_LEN);
  id->NONCE_LEN = uint8_array_to_number(uint8NumberArray);

  free(uint8NumberArray);

  if (ARRAY_LEN
      != 2 * UINT8_NUMBER_LEN + id->IDENTITIES_LEN * id->NONCE_LEN
             + id->IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES
             + id->IDENTITIES_LEN * crypto_sign_ed25519_SECRETKEYBYTES
             + 3 * crypto_hash_sha512_BYTES)
    return -2;

  memcpy(id->reversible_commit_details, &array[2 * UINT8_NUMBER_LEN],
         2 * crypto_hash_sha512_BYTES);
  memcpy(id->irreversible_commit_details,
         &array[2 * UINT8_NUMBER_LEN + 2 * crypto_hash_sha512_BYTES],
         crypto_hash_sha512_BYTES);
  memcpy(id->nonces,
         &array[2 * UINT8_NUMBER_LEN + 3 * crypto_hash_sha512_BYTES],
         id->IDENTITIES_LEN * id->NONCE_LEN);
  memcpy(&id->public_keys[0],
         &array[2 * UINT8_NUMBER_LEN + 2 * crypto_hash_sha512_BYTES
                + id->IDENTITIES_LEN * id->NONCE_LEN],
         id->IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES);
  memcpy(&id->secret_keys[0],
         &array[2 * UINT8_NUMBER_LEN + 2 * crypto_hash_sha512_BYTES
                + id->IDENTITIES_LEN * id->NONCE_LEN
                + id->IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES],
         id->IDENTITIES_LEN * crypto_sign_ed25519_SECRETKEYBYTES);

  return 0;
}
