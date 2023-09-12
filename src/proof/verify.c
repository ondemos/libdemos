#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../utils/utils.h"

#include "./proof.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int
verify_ownership_proof(const unsigned int PROOF_LEN,
                       const uint8_t commitment[crypto_hash_sha512_BYTES],
                       const uint8_t proof[PROOF_LEN])
{
  size_t i;

  ownership_proof *p = deserialize_proof(PROOF_LEN, proof);
  if (p == NULL) return -1;

  uint8_t *concat_hashes
      = malloc(sizeof(uint8_t[2 * crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL)
  {
    free_proof(p);

    return -8;
  }

  uint8_t *hash = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free_proof(p);
    free(concat_hashes);

    return -9;
  }

  uint8_t *ownership_ladder = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (ownership_ladder == NULL)
  {
    free_proof(p);
    free(concat_hashes);
    free(hash);

    return -10;
  }

  int res;

  if (p->number_of_artifacts_between_public_key_and_previous_commit != 0)
  {
    uint8_t(*artifacts_between_public_key_and_previous_commit)
        [crypto_hash_sha512_BYTES]
        = malloc(sizeof(
            uint8_t
                [p->number_of_artifacts_between_public_key_and_previous_commit]
                [crypto_hash_sha512_BYTES]));
    if (artifacts_between_public_key_and_previous_commit == NULL)
    {
      free_proof(p);
      free(concat_hashes);
      free(hash);
      free(ownership_ladder);

      return -11;
    }

    memcpy(&artifacts_between_public_key_and_previous_commit[0],
           &p->ownership_ladder_artifacts[0],
           p->number_of_artifacts_between_public_key_and_previous_commit
               * crypto_hash_sha512_BYTES);

    memcpy(&ownership_ladder[0],
           &artifacts_between_public_key_and_previous_commit[0],
           crypto_hash_sha512_BYTES);

    for (i = 1;
         i < p->number_of_artifacts_between_public_key_and_previous_commit; i++)
    {
      memcpy(&concat_hashes[0],
             &artifacts_between_public_key_and_previous_commit[i],
             crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &ownership_ladder[0],
             crypto_hash_sha512_BYTES);

      res = crypto_hash_sha512(ownership_ladder, concat_hashes,
                               2 * crypto_hash_sha512_BYTES);
      if (res != 0)
      {
        free_proof(p);
        free(concat_hashes);
        free(hash);
        free(ownership_ladder);
        free(artifacts_between_public_key_and_previous_commit);

        return -12;
      }
    }

    free(artifacts_between_public_key_and_previous_commit);
  }

  uint8_t(
      *artifacts_between_commitment_and_public_key)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(
          uint8_t[p->number_of_artifacts_between_commitment_and_public_key]
                 [crypto_hash_sha512_BYTES]));
  if (artifacts_between_commitment_and_public_key == NULL)
  {
    free_proof(p);
    free(concat_hashes);
    free(hash);
    free(ownership_ladder);

    return -13;
  }

  memcpy(&artifacts_between_commitment_and_public_key[0],
         &p->ownership_ladder_artifacts
              [p->number_of_artifacts_between_public_key_and_previous_commit],
         p->number_of_artifacts_between_commitment_and_public_key
             * crypto_hash_sha512_BYTES);

  // First element of this array is the hashed nonce corresponding to the
  // prover.
  memcpy(&concat_hashes[0], &artifacts_between_commitment_and_public_key[0],
         crypto_hash_sha512_BYTES);

  res = crypto_hash_sha512(hash, p->public_key,
                           crypto_sign_ed25519_PUBLICKEYBYTES);
  if (res != 0)
  {
    free_proof(p);
    free(concat_hashes);
    free(hash);
    free(ownership_ladder);
    free(artifacts_between_commitment_and_public_key);

    return -14;
  }

  memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &hash[0],
         crypto_hash_sha512_BYTES);

  // Calculate hash of concatenation of nonce and prover public key hashes.
  res = crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
  if (res != 0)
  {
    free_proof(p);
    free(concat_hashes);
    free(hash);
    free(ownership_ladder);
    free(artifacts_between_commitment_and_public_key);

    return -15;
  }

  if (p->number_of_artifacts_between_public_key_and_previous_commit == 0)
  {
    memcpy(&ownership_ladder[0], &hash[0], crypto_hash_sha512_BYTES);
  }
  else
  {
    memcpy(&concat_hashes[0], &hash[0], crypto_hash_sha512_BYTES);
    memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &ownership_ladder[0],
           crypto_hash_sha512_BYTES);
    res = crypto_hash_sha512(ownership_ladder, concat_hashes,
                             2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free_proof(p);
      free(concat_hashes);
      free(hash);
      free(ownership_ladder);
      free(artifacts_between_commitment_and_public_key);

      return -16;
    }
  }

  for (i = 1; i < p->number_of_artifacts_between_commitment_and_public_key; i++)
  {
    memcpy(&concat_hashes[0], &artifacts_between_commitment_and_public_key[i],
           crypto_hash_sha512_BYTES);
    memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &ownership_ladder[0],
           crypto_hash_sha512_BYTES);
    res = crypto_hash_sha512(ownership_ladder, concat_hashes,
                             2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free_proof(p);
      free(concat_hashes);
      free(hash);
      free(ownership_ladder);
      free(artifacts_between_commitment_and_public_key);

      return -17;
    }
  }

  free(artifacts_between_commitment_and_public_key);

  memcpy(&concat_hashes[0], &ownership_ladder[0], crypto_hash_sha512_BYTES);
  memcpy(&concat_hashes[crypto_hash_sha512_BYTES], &p->previous_commit[0],
         crypto_hash_sha512_BYTES);
  res = crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
  if (res != 0)
  {
    free_proof(p);
    free(concat_hashes);
    free(hash);
    free(ownership_ladder);

    return -18;
  }

  free(ownership_ladder);

  res = memcmp(hash, commitment, crypto_hash_sha512_BYTES);
  free(hash);
  free(concat_hashes);
  if (res != 0)
  {
    free_proof(p);

    return -19;
  }

  res = crypto_sign_ed25519_verify_detached(
      p->signature, commitment, crypto_hash_sha512_BYTES, p->public_key);
  if (res != 0)
  {
    free_proof(p);

    return -20;
  }

  // This will be at least 0
  const unsigned int distance_of_identity_from_commitment
      = p->number_of_artifacts_between_commitment_and_public_key - 1;

  free_proof(p);

  // The higher it is, the more seniority an identity has from another
  return distance_of_identity_from_commitment;
}
