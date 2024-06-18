#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

int
verify_merkle_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t root[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)])
{
  int res;
  size_t i, position;

  if (PROOF_ARTIFACTS_LEN == 1)
  {
    res = memcmp(root, element_hash, crypto_hash_sha512_BYTES);
    if (res == 0)
    {
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

  uint8_t *hash = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(concat_hashes);

    return -2;
  }

  memcpy(hash, element_hash, crypto_hash_sha512_BYTES);

  /* for (i = 0; i < NODES_LEN; i++) */
  for (i = 0; i < PROOF_ARTIFACTS_LEN; i++)
  {
    position
        = proof[i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES];
    if (position != 0 && position != 1)
    {
      free(hash);
      free(concat_hashes);

      return -3;
    }

    // Proof artifact goes to the left
    if (position == 0)
    {
      memcpy(concat_hashes[0], &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
      memcpy(concat_hashes[1], hash, crypto_hash_sha512_BYTES);
    }
    else
    {
      memcpy(concat_hashes[0], hash, crypto_hash_sha512_BYTES);
      memcpy(concat_hashes[1], &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
    }

    res = crypto_hash_sha512(hash, concat_hashes[0],
                             2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(concat_hashes);
      free(hash);

      return -4;
    }
  }

  free(concat_hashes);
  res = memcmp(hash, root, crypto_hash_sha512_BYTES);
  free(hash);

  if (res != 0) return 1;

  return 0;
}
