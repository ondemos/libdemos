#include <stdlib.h>
#include <string.h>

#include "demos.h"

/**
 * The commit details are the HMAC sha512 of a public key and
 * its corresponding nonce.
 * For every identity, we hash the commit corresponding to
 * the previous identity and then use the result as the
 * key for the HMAC of this identity's public key.
 */
int
generate_commit_details(
    const unsigned int IDENTITIES_LEN,
    const uint8_t nonces[IDENTITIES_LEN * crypto_auth_hmacsha512_KEYBYTES],
    const uint8_t
        public_keys[IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES],
    uint8_t commit_details[crypto_auth_hmacsha512_BYTES])
{
  if (IDENTITIES_LEN < 1) return -1;

  // Calculate commit details for the first identity
  int res = crypto_auth_hmacsha512(commit_details, public_keys,
                                   crypto_sign_ed25519_PUBLICKEYBYTES, nonces);

  if (res != 0) return -2;

  if (IDENTITIES_LEN > 1)
  {
    // helper
    uint8_t *hash
        = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
    if (hash == NULL) return -3;

    for (size_t i = 1; i < IDENTITIES_LEN; i++)
    {
      // If IDENTITIES > 1 the receiver wants to have
      // a few extra keys that take precedence in the ownership order
      // from the one that the receiver has.
      // Calculate previous commit left leaf
      res = crypto_auth_hmacsha512(
          hash, commit_details, crypto_auth_hmacsha512_BYTES,
          &nonces[i * crypto_auth_hmacsha512_KEYBYTES]);
      if (res != 0)
      {
        free(hash);

        return -4;
      }

      // Calculate the commit details for this identity using the previous
      // hash as key
      res = crypto_auth_hmacsha512(
          commit_details, &public_keys[i * crypto_sign_ed25519_PUBLICKEYBYTES],
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
