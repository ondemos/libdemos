#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

int
get_merkle_root_from_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)],
    uint8_t root[crypto_hash_sha512_BYTES])
{
  memcpy(root, element_hash, crypto_hash_sha512_BYTES);

  size_t i;
  unsigned int position;
  int res;

  if (PROOF_ARTIFACTS_LEN == 1)
  {
    res = memcmp(proof, element_hash, crypto_hash_sha512_BYTES);
    if (res == 0)
    {
      memcpy(root, element_hash, crypto_hash_sha512_BYTES);

      return 0;
    }
    else
    {
      // If 1 artifact then either proof is the same
      // as the element hash, and therefore
      // the same as the root, or we have an error
      return -1;
    }
  }

  uint8_t(*concat_hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[2][crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL) return -1;

  for (i = 0; i < PROOF_ARTIFACTS_LEN; i++)
  {
    position
        = proof[i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES];

    // Proof artifact goes to the left
    if (position == 0)
    {
      memcpy(concat_hashes[0], &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
      memcpy(concat_hashes[1], root, crypto_hash_sha512_BYTES);
    }
    else if (position == 1)
    {
      memcpy(concat_hashes[0], root, crypto_hash_sha512_BYTES);
      memcpy(concat_hashes[1], &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
    }
    else
    {
      free(concat_hashes);

      return -2;
    }

    res = crypto_hash_sha512(root, concat_hashes[0],
                             2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(concat_hashes);

      return -3;
    }
  }

  free(concat_hashes);

  return 0;
}
