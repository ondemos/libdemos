#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "./proof.h"

#include "../utils/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

ownership_proof *
deserialize_proof(const size_t PROOF_LEN, const uint8_t proof[PROOF_LEN])
{
  if (PROOF_LEN < PROOF_MIN_LEN) return NULL;

  ownership_proof *p = malloc(sizeof(ownership_proof));
  if (p == NULL) return p;

  uint8_t *uint8NumberArray = malloc(sizeof(uint8_t[UINT8_NUMBER_LEN]));
  if (uint8NumberArray == NULL)
  {
    free(p);

    return NULL;
  }

  // Excluding the hashed nonce of the corresponding prover identity.
  const unsigned int
      number_of_artifacts_between_public_key_and_previous_commit_start_index
      = crypto_hash_sha512_BYTES;

  // This can be zero if this was a simple transfer from previous commitment.
  memcpy(
      uint8NumberArray,
      &proof
          [number_of_artifacts_between_public_key_and_previous_commit_start_index],
      UINT8_NUMBER_LEN);
  const unsigned int number_of_artifacts_between_public_key_and_previous_commit
      = uint8_array_to_number(uint8NumberArray);

  // Including the hashed nonce of the corresponding prover identity.
  const unsigned int
      number_of_artifacts_between_commitment_and_public_key_start_index
      = number_of_artifacts_between_public_key_and_previous_commit_start_index
        + UINT8_NUMBER_LEN;

  memcpy(
      uint8NumberArray,
      &proof[number_of_artifacts_between_commitment_and_public_key_start_index],
      UINT8_NUMBER_LEN);
  const unsigned int number_of_artifacts_between_commitment_and_public_key
      = uint8_array_to_number(uint8NumberArray);

  free(uint8NumberArray);

  // This needs to hold at least the hash of the nonce corresponding to the
  // public key.
  if (number_of_artifacts_between_commitment_and_public_key < 1)
  {
    free(p);

    return NULL;
  }

  p->number_of_artifacts_between_commitment_and_public_key
      = number_of_artifacts_between_commitment_and_public_key;
  p->number_of_artifacts_between_public_key_and_previous_commit
      = number_of_artifacts_between_public_key_and_previous_commit;

  const unsigned int number_of_ownership_ladder_artifacts
      = p->number_of_artifacts_between_commitment_and_public_key
        + p->number_of_artifacts_between_public_key_and_previous_commit;

  if (PROOF_LEN
      != (1 + number_of_ownership_ladder_artifacts) * crypto_hash_sha512_BYTES
             + 2 * UINT8_NUMBER_LEN + crypto_sign_ed25519_PUBLICKEYBYTES
             + crypto_sign_ed25519_BYTES)
  {
    free(p);

    return NULL;
  }

  memcpy(&p->previous_commit[0], &proof[0], crypto_hash_sha512_BYTES);

  const unsigned int signature_start_index
      = PROOF_LEN - crypto_sign_ed25519_BYTES;
  memcpy(&p->signature[0], &proof[signature_start_index],
         crypto_sign_ed25519_BYTES);

  const unsigned int public_key_start_index
      = signature_start_index - crypto_sign_ed25519_PUBLICKEYBYTES;
  memcpy(&p->public_key[0], &proof[public_key_start_index],
         crypto_sign_ed25519_PUBLICKEYBYTES);

  p->ownership_ladder_artifacts = malloc(sizeof(
      uint8_t[number_of_ownership_ladder_artifacts][crypto_hash_sha512_BYTES]));
  if (p->ownership_ladder_artifacts == NULL)
  {
    free(p);

    return NULL;
  }

  const unsigned int ownership_ladder_artifacts_start_index
      = number_of_artifacts_between_commitment_and_public_key_start_index
        + UINT8_NUMBER_LEN;

  for (unsigned int i = 0; i < number_of_ownership_ladder_artifacts; i++)
  {
    memcpy(&p->ownership_ladder_artifacts[i],
           &proof[ownership_ladder_artifacts_start_index
                  + i * crypto_hash_sha512_BYTES],
           crypto_hash_sha512_BYTES);
  }

  return p;
}
