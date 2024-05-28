#include <stdlib.h>
#include <string.h>

#include "demos.h"

#include "../libsodium/src/libsodium/include/sodium/randombytes.h"

/**
 * Reversible and irreversible have the same length so that
 * a transfer and a delegation are indistinguishable
 */
int
generate_identities(
    const unsigned int IDENTITIES_LEN,
    uint8_t nonces[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES],
    uint8_t public_keys[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES],
    uint8_t secret_keys[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t commit_details[crypto_auth_hmacsha512_BYTES])
{
  if (IDENTITIES_LEN < 1) return -1;

  randombytes_buf(nonces[0], crypto_auth_hmacsha512_KEYBYTES);
  crypto_sign_ed25519_keypair(public_keys[0], secret_keys[0]);

  int res
      = crypto_auth_hmacsha512(commit_details, public_keys[0],
                               crypto_sign_ed25519_PUBLICKEYBYTES, nonces[0]);

  if (res != 0) return -2;

  if (IDENTITIES_LEN > 1)
  {
    uint8_t *hash
        = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
    if (hash == NULL) return -3;

    // Populate random nonces and public/secret keypairs
    for (size_t i = 1; i < IDENTITIES_LEN; i++)
    {
      randombytes_buf(nonces[i], crypto_auth_hmacsha512_KEYBYTES);
      crypto_sign_ed25519_keypair(public_keys[i], secret_keys[i]);

      // For the external details we calculate the nonce differently
      // because for IDENTITIES > 1 the receiver wants to have
      // a few extra keys that take precedence in the ownership order
      // from the one that the receiver has
      // Calculate previous commit left leaf
      res = crypto_auth_hmacsha512(hash, commit_details,
                                   crypto_auth_hmacsha512_BYTES, nonces[i]);
      if (res != 0)
      {
        free(hash);

        return -4;
      }

      res = crypto_auth_hmacsha512(commit_details, public_keys[i],
                                   crypto_sign_ed25519_PUBLICKEYBYTES, hash);
      if (res != 0)
      {
        free(hash);

        return -5;
      }
    }

    free(hash);
  }

  return 0;
}
