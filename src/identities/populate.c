#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../libsodium/src/libsodium/include/sodium/randombytes.h"

/**
 * In order to generate commit details, the receiver decides how many random
 * keypairs need to exist between the owning keypair of the previous commit and
 * the next one.
 * Nonces, public keys and secret keys go from oldest to latest in the chain of
 * custody.
 */
int
populate_identity(
    const unsigned int IDENTITIES_LEN, const unsigned int NONCE_LEN,
    uint8_t nonces[IDENTITIES_LEN][NONCE_LEN],
    uint8_t public_keys[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES],
    uint8_t secret_keys[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t reversible_details[2 * crypto_hash_sha512_BYTES],
    uint8_t irreversible_details[crypto_hash_sha512_BYTES])
{
  if (IDENTITIES_LEN < 1) return -1;

  size_t i;

  int res;

  const unsigned int len = 2 * crypto_hash_sha512_BYTES;
  uint8_t *concat_hashes = malloc(sizeof(uint8_t[len]));
  if (concat_hashes == NULL) return -2;

  uint8_t *hash = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(concat_hashes);

    return -3;
  }

  uint8_t *commit_tracker = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (commit_tracker == NULL)
  {
    free(concat_hashes);
    free(hash);

    return -4;
  }

  for (i = 0; i < IDENTITIES_LEN; i++)
  {
    // Populate random nonces and public/secret keypairs
    randombytes_buf(nonces[i], NONCE_LEN);
    crypto_sign_ed25519_keypair(public_keys[i], secret_keys[i]);

    // First calculate nonce hash
    res = crypto_hash_sha512(hash, nonces[i], NONCE_LEN);
    if (res != 0)
    {
      free(concat_hashes);
      free(hash);
      free(commit_tracker);

      return -5;
    }

    memcpy(&concat_hashes[0], &hash[0], crypto_hash_sha512_BYTES);

    // Second calculate public key hash
    res = crypto_hash_sha512(hash, public_keys[i],
                             crypto_sign_ed25519_PUBLICKEYBYTES);
    if (res != 0)
    {
      free(concat_hashes);
      free(hash);
      free(commit_tracker);

      return -6;
    }

    memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &hash[0],
           crypto_hash_sha512_BYTES);

    // Third calculate hash of concatenation of nonce and public
    // key hashes.
    res = crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(concat_hashes);
      free(hash);
      free(commit_tracker);

      return -7;
    }

    if (i == 0)
    {
      memcpy(&commit_tracker[0], &hash[0], crypto_hash_sha512_BYTES);
    }
    else
    {
      memcpy(&concat_hashes[0], &hash[0], crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &commit_tracker[0],
             crypto_hash_sha512_BYTES);

      res = crypto_hash_sha512(commit_tracker, concat_hashes,
                               2 * crypto_hash_sha512_BYTES);
      if (res != 0)
      {
        free(concat_hashes);
        free(hash);
        free(commit_tracker);

        return -8;
      }
    }
  }

  free(hash);

  // The hash of the last concatenation is the details of a potential future
  // irreversible transaction.
  memcpy(&irreversible_details[0], &commit_tracker[0],
         crypto_hash_sha512_BYTES);
  free(commit_tracker);

  // The last concatenation is the details of a potential future reversible
  // transaction.
  memcpy(&reversible_details[0], &concat_hashes[0],
         2 * crypto_hash_sha512_BYTES);
  free(concat_hashes);

  return 0;
}
