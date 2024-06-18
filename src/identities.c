#include "demos.h"
#include "utils/utils.h"

/**
 * Generate public-secret keypairs and nonces to calculate commit details.
 */
int
generate_identities(
    const unsigned int IDENTITIES_LEN,
    uint8_t nonces[IDENTITIES_LEN * crypto_auth_hmacsha512_KEYBYTES],
    uint8_t public_keys[IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES],
    uint8_t secret_keys[IDENTITIES_LEN * crypto_sign_ed25519_SECRETKEYBYTES])
{
  int res;
  if (IDENTITIES_LEN < 1) return -1;

  // Generate nonce and public-secret keypair for the first identity
  res = random_bytes(crypto_auth_hmacsha512_KEYBYTES, &nonces[0]);
  if (res != 0) return -2;

  res = crypto_sign_ed25519_keypair(&public_keys[0], &secret_keys[0]);
  if (res != 0) return -3;

  if (IDENTITIES_LEN > 1)
  {
    // Populate random nonces and public/secret keypairs
    for (size_t i = 1; i < IDENTITIES_LEN; i++)
    {
      res = random_bytes(crypto_auth_hmacsha512_KEYBYTES,
                         &nonces[i * crypto_auth_hmacsha512_KEYBYTES]);
      if (res != 0) return -4;

      res = crypto_sign_ed25519_keypair(
          &public_keys[i * crypto_sign_ed25519_PUBLICKEYBYTES],
          &secret_keys[i * crypto_sign_ed25519_SECRETKEYBYTES]);
      if (res != 0) return -5;
    }
  }

  return 0;
}
