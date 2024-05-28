#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demos.h"

#include "../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int
verify_proof(const unsigned int PROOF_LEN,
             const uint8_t current_commit[crypto_hash_sha512_BYTES],
             const uint8_t proof[PROOF_LEN])
{
  if (PROOF_LEN < crypto_hash_sha512_BYTES + crypto_sign_ed25519_PUBLICKEYBYTES
                      + crypto_auth_hmacsha512_KEYBYTES
                      + crypto_sign_ed25519_BYTES)
    return -1;

  const unsigned int IDENTITIES_DETAILS_LEN
      = PROOF_LEN - crypto_hash_sha512_BYTES - crypto_sign_ed25519_BYTES;

  const unsigned int modulo = IDENTITIES_DETAILS_LEN
                              % (crypto_sign_ed25519_PUBLICKEYBYTES
                                 + crypto_auth_hmacsha512_KEYBYTES);

  if (modulo != 0) return -2;

  const unsigned int IDENTITIES_LEN = IDENTITIES_DETAILS_LEN
                                      / (crypto_sign_ed25519_PUBLICKEYBYTES
                                         + crypto_auth_hmacsha512_KEYBYTES);
  printf("Identities len is %d\n", IDENTITIES_LEN);

  if (PROOF_LEN > crypto_hash_sha512_BYTES
                      + IDENTITIES_LEN
                            * (crypto_sign_ed25519_PUBLICKEYBYTES
                               + crypto_auth_hmacsha512_KEYBYTES)
                      + crypto_sign_ed25519_BYTES)
    return -3;

  uint8_t *hash_1
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (hash_1 == NULL) return -4;

  uint8_t *hash_2
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (hash_2 == NULL)
  {
    free(hash_1);

    return -5;
  }

  int res = crypto_auth_hmacsha512(
      hash_1, &proof[crypto_hash_sha512_BYTES],
      crypto_sign_ed25519_PUBLICKEYBYTES,
      &proof[crypto_hash_sha512_BYTES + crypto_sign_ed25519_PUBLICKEYBYTES]);
  if (res != 0)
  {
    free(hash_1);
    free(hash_2);

    return -6;
  }

  for (size_t i = 1; i < IDENTITIES_LEN; i++)
  {
    res = crypto_auth_hmacsha512(
        hash_2, hash_1, crypto_auth_hmacsha512_BYTES,
        &proof[crypto_hash_sha512_BYTES
               + i
                     * (crypto_sign_ed25519_PUBLICKEYBYTES
                        + crypto_auth_hmacsha512_KEYBYTES)
               + crypto_sign_ed25519_PUBLICKEYBYTES]);
    if (res != 0)
    {
      free(hash_1);
      free(hash_2);

      return -7;
    }

    res = crypto_auth_hmacsha512(
        hash_1,
        &proof[crypto_hash_sha512_BYTES
               + i
                     * (crypto_sign_ed25519_PUBLICKEYBYTES
                        + crypto_auth_hmacsha512_KEYBYTES)],
        crypto_sign_ed25519_PUBLICKEYBYTES, hash_2);
    if (res != 0)
    {
      free(hash_1);
      free(hash_2);

      return -8;
    }
  }

  res = commit(hash_2, proof, hash_1);
  free(hash_1);
  if (res != 0)
  {
    free(hash_2);

    return -9;
  }

  res = memcmp(current_commit, hash_2, crypto_hash_sha512_BYTES);
  free(hash_2);
  if (res != 0) return -10;

  return IDENTITIES_LEN;
}
