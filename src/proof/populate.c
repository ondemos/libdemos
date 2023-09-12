#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "./proof.h"

#include "../utils/utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

/**
 * In order to generate commit details, the receiver decides how many random
 * keypairs need to exist between the owning keypair of the previous commit and
 * the next one.
 */
int
generate_ownership_proof(
    const unsigned int PROOF_LEN, const unsigned int IDENTITIES_LEN,
    const unsigned int NONCE_LEN,
    const uint8_t commitment[crypto_hash_sha512_BYTES],
    const uint8_t previous_commit[crypto_hash_sha512_BYTES],
    const uint8_t nonces[IDENTITIES_LEN][NONCE_LEN],
    const uint8_t public_keys[IDENTITIES_LEN]
                             [crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    uint8_t proof[PROOF_LEN])
{
  if (IDENTITIES_LEN == 0) return -1;

  if (PROOF_LEN
      != (1 + IDENTITIES_LEN) * crypto_hash_sha512_BYTES + 2 * UINT8_NUMBER_LEN
             + crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES)
    return -2;

  size_t i, j, required_key_index;

  int res;
  bool pk_found = false;

  uint8_t *public_key
      = malloc(sizeof(uint8_t[crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (public_key == NULL) return -3;
  memcpy(public_key, secret_key + crypto_sign_ed25519_SEEDBYTES,
         crypto_sign_ed25519_PUBLICKEYBYTES);

  for (i = 0; i < IDENTITIES_LEN; i++)
  {
    res = memcmp(public_keys[i], public_key,
                 crypto_sign_ed25519_PUBLICKEYBYTES);
    if (res != 0)
    {
      continue;
    }
    else
    {
      pk_found = true;
      required_key_index = i;

      break;
    }
  }

  if (!pk_found)
  {
    free(public_key);

    return -4;
  }

  const unsigned int previous_commit_index = 0;

  memcpy(&proof[previous_commit_index], previous_commit,
         crypto_hash_sha512_BYTES);

  uint8_t *numberArray = malloc(sizeof(uint8_t[UINT8_NUMBER_LEN]));
  if (numberArray == NULL)
  {
    free(public_key);

    return -5;
  }

  // The number of artifacts between previous commitment and public key
  // excluding the hashed nonce.
  number_to_uint8_array(required_key_index, numberArray);
  const unsigned int number_of_artifacts_between_public_key_and_previous_commit
      = previous_commit_index + crypto_hash_sha512_BYTES;
  memcpy(&proof[number_of_artifacts_between_public_key_and_previous_commit],
         numberArray, UINT8_NUMBER_LEN);

  // The number of artifacts between commitment and public key including
  // the hashed nonce.
  number_to_uint8_array(IDENTITIES_LEN - required_key_index, numberArray);
  const unsigned int number_of_artifacts_between_commitment_and_public_key
      = number_of_artifacts_between_public_key_and_previous_commit
        + UINT8_NUMBER_LEN;
  memcpy(&proof[number_of_artifacts_between_commitment_and_public_key],
         numberArray, UINT8_NUMBER_LEN);
  free(numberArray);

  uint8_t *concat_hashes
      = malloc(sizeof(uint8_t[2 * crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL)
  {
    free(public_key);

    return -6;
  }

  uint8_t *hash = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(concat_hashes);
    free(public_key);

    return -7;
  }

  unsigned int artifact_index
      = number_of_artifacts_between_commitment_and_public_key
        + UINT8_NUMBER_LEN;

  for (i = 0; i < IDENTITIES_LEN; i++)
  {
    // Calculate nonce hash and put on the left side of concatenation
    res = crypto_hash_sha512(hash, nonces[i], NONCE_LEN);
    if (res != 0)
    {
      free(hash);
      free(concat_hashes);
      free(public_key);

      return -8;
    }

    // In case the secret key's identity is paired with this nonce then
    // we only include the nonce's hash in the proof.
    if (i == required_key_index)
    {
      memcpy(&proof[artifact_index], hash, crypto_hash_sha512_BYTES);

      artifact_index += crypto_hash_sha512_BYTES;

      continue;
    }

    memcpy(concat_hashes, hash, crypto_hash_sha512_BYTES);

    // Calculate public key hash and put on the right side of concatenation
    res = crypto_hash_sha512(hash, public_keys[i],
                             crypto_sign_ed25519_PUBLICKEYBYTES);
    if (res != 0)
    {
      free(hash);
      free(concat_hashes);
      free(public_key);

      return -9;
    }

    memcpy(&concat_hashes[crypto_hash_sha512_BYTES], hash,
           crypto_hash_sha512_BYTES);

    // Calculate hash of concatenation of hashes
    res = crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(hash);
      free(concat_hashes);
      free(public_key);

      return -10;
    }

    // We only include the hash of the concatenated details in the proof
    // if the identity's credential is not the prover key.
    memcpy(&proof[artifact_index], hash, crypto_hash_sha512_BYTES);

    artifact_index += crypto_hash_sha512_BYTES;
  }

  free(hash);
  free(concat_hashes);

  memcpy(&proof[artifact_index], public_key,
         crypto_sign_ed25519_PUBLICKEYBYTES);
  free(public_key);

  uint8_t *signature = malloc(crypto_sign_ed25519_BYTES);
  if (signature == NULL) return -11;

  unsigned long long SIGNATURE_LEN = crypto_sign_ed25519_BYTES;
  res = crypto_sign_ed25519_detached(signature, &SIGNATURE_LEN, commitment,
                                     crypto_hash_sha512_BYTES, secret_key);
  if (res != 0)
  {
    free(signature);

    return -12;
  }

  const unsigned int signature_index
      = artifact_index + crypto_sign_ed25519_PUBLICKEYBYTES;

  memcpy(&proof[signature_index], signature, crypto_sign_ed25519_BYTES);

  free(signature);

  return 0;
}
