#include <stdbool.h>
#include <string.h>

#include "demos.h"

#include "utils/utils.h"

/**
 * In order to generate commit details, the receiver decides how many random
 * keypairs need to exist between the owning keypair of the previous commit and
 * the next one.
 */
int
generate_proof(
    const unsigned int PROOF_LEN, const unsigned int IDENTITIES_LEN,
    const uint8_t current_commit[crypto_hash_sha512_BYTES],
    const uint8_t previous_commit[crypto_hash_sha512_BYTES],
    const uint8_t nonces[IDENTITIES_LEN * crypto_auth_hmacsha512_KEYBYTES],
    const uint8_t
        public_keys[IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t proof[PROOF_LEN])
{
  if (IDENTITIES_LEN == 0) return -1;

  if (PROOF_LEN
          < crypto_hash_sha512_BYTES                 // previous commit
                + crypto_sign_ed25519_PUBLICKEYBYTES // public key of commit
                + crypto_auth_hmacsha512_KEYBYTES    // nonce of this commit
                + crypto_sign_ed25519_BYTES // signature verifiable by pk
      || PROOF_LEN > crypto_hash_sha512_BYTES
                         + IDENTITIES_LEN
                               * (crypto_sign_ed25519_PUBLICKEYBYTES
                                  + crypto_auth_hmacsha512_KEYBYTES)
                         + crypto_sign_ed25519_BYTES)
    return -2;

  size_t i, j, required_key_index;

  int res;
  bool pk_found = false;

  for (i = 0; i < IDENTITIES_LEN; i++)
  {
    res = memcmp(&public_keys[i * crypto_sign_ed25519_PUBLICKEYBYTES],
                 &secret_key[crypto_sign_ed25519_SEEDBYTES],
                 crypto_sign_ed25519_PUBLICKEYBYTES);
    if (res != 0) continue;

    pk_found = true;
    required_key_index = i;

    break;
  }

  if (!pk_found) return -3;

  if (PROOF_LEN
      != crypto_hash_sha512_BYTES
             + (IDENTITIES_LEN - required_key_index)
                   * (crypto_sign_ed25519_PUBLICKEYBYTES
                      + crypto_auth_hmacsha512_KEYBYTES)
             + crypto_sign_ed25519_BYTES)
    return -4;

  // First part of the proof array is the previous commit
  memcpy(&proof[0], &previous_commit[0], crypto_hash_sha512_BYTES);

  // Second part is the first public key in the ladder which will sign the proof
  memcpy(&proof[crypto_hash_sha512_BYTES],
         &public_keys[required_key_index * crypto_sign_ed25519_PUBLICKEYBYTES],
         crypto_sign_ed25519_PUBLICKEYBYTES);

  uint8_t *hash_1
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (hash_1 == NULL) return -5;

  uint8_t *hash_2
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (hash_2 == NULL)
  {
    free(hash_1);

    return -6;
  }

  // First public key and nonce from identities
  res = crypto_auth_hmacsha512(hash_1, &public_keys[0],
                               crypto_sign_ed25519_PUBLICKEYBYTES, &nonces[0]);
  if (res != 0)
  {
    free(hash_1);
    free(hash_2);

    return -7;
  }

  if (required_key_index == 0)
  {
    memcpy(
        &proof[crypto_hash_sha512_BYTES + crypto_sign_ed25519_PUBLICKEYBYTES],
        &nonces[0], crypto_auth_hmacsha512_KEYBYTES);
  }

  j = 1;
  for (i = 1; i < IDENTITIES_LEN; i++)
  {
    res = crypto_auth_hmacsha512(hash_2, hash_1, crypto_auth_hmacsha512_BYTES,
                                 &nonces[i * crypto_auth_hmacsha512_KEYBYTES]);
    if (res != 0)
    {
      free(hash_1);
      free(hash_2);

      return -8;
    }

    res = crypto_auth_hmacsha512(
        hash_1, &public_keys[i * crypto_sign_ed25519_PUBLICKEYBYTES],
        crypto_sign_ed25519_PUBLICKEYBYTES, hash_2);
    if (res != 0)
    {
      free(hash_1);
      free(hash_2);

      return -9;
    }

    if (i == required_key_index)
    {
      memcpy(
          &proof[crypto_hash_sha512_BYTES + crypto_sign_ed25519_PUBLICKEYBYTES],
          hash_2, crypto_auth_hmacsha512_KEYBYTES);
    }
    else if (i > required_key_index)
    {
      memcpy(&proof[crypto_hash_sha512_BYTES
                    + j
                          * (crypto_sign_ed25519_PUBLICKEYBYTES
                             + crypto_auth_hmacsha512_KEYBYTES)],
             &public_keys[i * crypto_sign_ed25519_PUBLICKEYBYTES],
             crypto_sign_ed25519_PUBLICKEYBYTES);
      memcpy(&proof[crypto_hash_sha512_BYTES
                    + j
                          * (crypto_sign_ed25519_PUBLICKEYBYTES
                             + crypto_auth_hmacsha512_KEYBYTES)
                    + crypto_sign_ed25519_PUBLICKEYBYTES],
             &nonces[i * crypto_auth_hmacsha512_KEYBYTES],
             crypto_auth_hmacsha512_KEYBYTES);

      j++;
    }
  }

  res = commit(hash_2, previous_commit, hash_1);
  free(hash_1);
  if (res != 0)
  {
    free(hash_2);

    return -10;
  }

  res = memcmp(current_commit, hash_2, crypto_hash_sha512_BYTES);
  free(hash_2);
  if (res != 0) return -11;

  res = sign(crypto_hash_sha512_BYTES, current_commit, secret_key,
             &proof[PROOF_LEN - crypto_sign_ed25519_BYTES]);
  if (res != 0) return -12;

  return 0;
}
