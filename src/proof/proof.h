#ifndef proof_H
#define proof_H

#include <stdbool.h>
#include <stdint.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

#define PROOF_MIN_LEN                                                          \
  2 * crypto_hash_sha512_BYTES + 2 * UINT8_NUMBER_LEN                          \
      + crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES

typedef struct Proof
{
  uint8_t previous_commit[crypto_hash_sha512_BYTES];
  unsigned int number_of_artifacts_between_commitment_and_public_key;
  unsigned int number_of_artifacts_between_public_key_and_previous_commit;
  uint8_t (*ownership_ladder_artifacts)[crypto_hash_sha512_BYTES];
  uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES];
  uint8_t signature[crypto_sign_ed25519_BYTES];
} ownership_proof;

void free_proof(struct Proof *p);
ownership_proof *deserialize_proof(const size_t PROOF_LEN,
                                   const uint8_t proof[PROOF_LEN]);

#endif
