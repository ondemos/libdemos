#include <stddef.h>
#include <string.h>

#include "./identities.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../libsodium/src/libsodium/include/sodium/randombytes.h"

identity *
new_identity(const unsigned int IDENTITIES_LEN, const unsigned int NONCE_LEN)
{
  if (IDENTITIES_LEN < 1) return NULL;

  identity *id = malloc(sizeof(identity));
  if (id == NULL) return id;

  id->IDENTITIES_LEN = IDENTITIES_LEN;
  id->NONCE_LEN = NONCE_LEN;

  id->nonces = malloc(sizeof(uint8_t[IDENTITIES_LEN][NONCE_LEN]));
  if (id->nonces == NULL)
  {
    free(id);

    return NULL;
  }

  id->public_keys = malloc(
      sizeof(uint8_t[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (id->public_keys == NULL)
  {
    free(id->nonces);
    free(id);

    return NULL;
  }

  id->secret_keys = malloc(
      sizeof(uint8_t[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES]));
  if (id->secret_keys == NULL)
  {
    free(id->public_keys);
    free(id->nonces);
    free(id);

    return NULL;
  }

  uint8_t *concat_hashes
      = malloc(sizeof(uint8_t[2 * crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL)
  {
    free(id->secret_keys);
    free(id->public_keys);
    free(id->nonces);
    free(id);

    return NULL;
  }

  uint8_t *hash = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(concat_hashes);
    free(id->secret_keys);
    free(id->public_keys);
    free(id->nonces);
    free(id);

    return NULL;
  }

  uint8_t *commit_tracker = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (commit_tracker == NULL)
  {
    free(hash);
    free(concat_hashes);
    free(id->secret_keys);
    free(id->public_keys);
    free(id->nonces);
    free(id);

    return NULL;
  }

  int res;

  for (unsigned int i = 0; i < IDENTITIES_LEN; i++)
  {
    // Populate random nonces and public/secret keypairs
    randombytes_buf(&id->nonces[i * NONCE_LEN], NONCE_LEN);
    crypto_sign_ed25519_keypair(id->public_keys[i], id->secret_keys[i]);

    // First calculate nonce hash
    res = crypto_hash_sha512(hash, &id->nonces[i * NONCE_LEN], NONCE_LEN);
    if (res != 0)
    {
      free(commit_tracker);
      free(hash);
      free(concat_hashes);
      free(id->secret_keys);
      free(id->public_keys);
      free(id->nonces);
      free(id);

      return NULL;
    }

    memcpy(&concat_hashes[0], &hash[0], crypto_hash_sha512_BYTES);

    // Second calculate public key hash
    res = crypto_hash_sha512(hash, id->public_keys[i],
                             crypto_sign_ed25519_PUBLICKEYBYTES);
    if (res != 0)
    {
      free(commit_tracker);
      free(hash);
      free(concat_hashes);
      free(id->secret_keys);
      free(id->public_keys);
      free(id->nonces);
      free(id);

      return NULL;
    }

    memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &hash[0],
           crypto_hash_sha512_BYTES);

    // Third calculate hash of concatenation of nonce and public
    // key hashes.
    res = crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(commit_tracker);
      free(hash);
      free(concat_hashes);
      free(id->secret_keys);
      free(id->public_keys);
      free(id->nonces);
      free(id);

      return NULL;
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
        free(commit_tracker);
        free(hash);
        free(concat_hashes);
        free(id->secret_keys);
        free(id->public_keys);
        free(id->nonces);
        free(id);

        return NULL;
      }
    }
  }

  free(hash);

  // The hash of the last concatenation is the details of a potential future
  // irreversible transaction.
  memcpy(id->irreversible_commit_details, &commit_tracker[0],
         crypto_hash_sha512_BYTES);
  free(commit_tracker);

  // The last concatenation is the details of a potential future reversible
  // transaction.
  memcpy(id->reversible_commit_details, &concat_hashes[0],
         2 * crypto_hash_sha512_BYTES);
  free(concat_hashes);

  return id;
}
