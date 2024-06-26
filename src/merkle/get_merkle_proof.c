#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

// The result is the proof length
int
get_merkle_proof(
    const unsigned int LEAVES_LEN,
    const uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    uint8_t proof[LEAVES_LEN * (crypto_hash_sha512_BYTES + 1)])
{
  int res, index = -1;
  size_t i, j, k;

  for (i = 0; i < LEAVES_LEN; i++)
  {
    res = memcmp(&leaves_hashed[i * crypto_hash_sha512_BYTES], element_hash,
                 crypto_hash_sha512_BYTES);

    if (res != 0) continue;

    index = i;
    break;
  }

  if (index == -1) return -1;

  memset(proof, 0, LEAVES_LEN * (crypto_hash_sha512_BYTES + 1));

  unsigned int element_of_interest = index;

  uint8_t(*hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[LEAVES_LEN][crypto_hash_sha512_BYTES]));
  if (hashes == NULL) return -2;

  memcpy(hashes, leaves_hashed, LEAVES_LEN * crypto_hash_sha512_BYTES);

  uint8_t(*concat_hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[2][crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL)
  {
    free(hashes);

    return -3;
  }

  unsigned int leaves = LEAVES_LEN;
  bool odd_leaves;

  // Counts the index of proof artifacts.
  k = 0;

  while (leaves > 1)
  {
    // Check if number of leaves is odd or even.
    odd_leaves = leaves % 2 != 0;

    // For every two leaves.
    for (i = 0, j = 0; i < leaves; i += 2, j++)
    {
      // If we are at the last position to the right of a tree with odd
      // number of leaves.
      if (odd_leaves && i + 1 == leaves)
      {
        memcpy(concat_hashes[0], hashes[i], crypto_hash_sha512_BYTES);
        // Concat leaf hash with itself.
        memcpy(concat_hashes[1], hashes[i], crypto_hash_sha512_BYTES);

        if (i == element_of_interest)
        {
          // Copy required hash of interest in the proof.
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)], hashes[i],
                 crypto_hash_sha512_BYTES);
          // We do not care if left(0) or right(1) since hash of itself
          // proof[k][crypto_hash_sha512_BYTES] = 0;

          k++;
          element_of_interest = j;
        }
      }
      else
      {
        memcpy(concat_hashes[0], hashes[i], crypto_hash_sha512_BYTES);
        // In any other case concat leaf hash with the one on its right.
        memcpy(concat_hashes[1], hashes[i + 1], crypto_hash_sha512_BYTES);

        if (i == element_of_interest || i + 1 == element_of_interest)
        {
          if (i == element_of_interest)
          {
            memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)], hashes[i + 1],
                   crypto_hash_sha512_BYTES);
            // Proof artifact needs to go to the right when concatenated with
            // element.
            proof[k * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
                = 1;
          }
          else if (i + 1 == element_of_interest)
          {
            memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)], hashes[i],
                   crypto_hash_sha512_BYTES);
            // Proof artifact needs to go to the left when concatenated with
            // element.
            // proof[k][crypto_hash_sha512_BYTES] = 0;
          }

          k++;
          element_of_interest = j;
        }
      }

      res = crypto_hash_sha512(hashes[j], concat_hashes[0],
                               2 * crypto_hash_sha512_BYTES);
      if (res != 0)
      {
        free(hashes);
        free(concat_hashes);

        return -4;
      }
    }

    leaves = ceil((double)leaves / 2);
  }

  free(hashes);
  free(concat_hashes);

  return k * (crypto_hash_sha512_BYTES + 1);
}
