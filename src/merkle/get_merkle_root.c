#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

int
get_merkle_root(
    const unsigned int LEAVES_LEN,
    const uint8_t leaves_hashed[LEAVES_LEN][crypto_hash_sha512_BYTES],
    uint8_t root[crypto_hash_sha512_BYTES])
{
  size_t i, j;

  uint8_t(*hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[LEAVES_LEN][crypto_hash_sha512_BYTES]));
  if (hashes == NULL) return -1;

  memcpy(hashes, leaves_hashed, LEAVES_LEN * crypto_hash_sha512_BYTES);

  uint8_t(*concat_hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[2][crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL)
  {
    free(hashes);

    return -2;
  }

  unsigned int leaves = LEAVES_LEN;
  int res;
  bool oddLeaves;

  // For every branch level.
  while (leaves > 0)
  {
    // Check if number of leaves is odd or even.
    oddLeaves = leaves % 2 != 0;

    // For every two leaves.
    for (i = 0, j = 0; i < leaves; i += 2, j++)
    {
      // We are at the last position to the right of a tree with odd number of
      // leaves.
      if (oddLeaves && i + 1 == leaves)
      {
        memcpy(&concat_hashes[0], &hashes[i][0], crypto_hash_sha512_BYTES);
        // Concat leaf hash with itself.
        memcpy(&concat_hashes[1], &hashes[i][0], crypto_hash_sha512_BYTES);
      }
      else
      {
        memcpy(&concat_hashes[0], &hashes[i][0], crypto_hash_sha512_BYTES);
        // In any other case concat leaf hash with the one on its right.
        memcpy(&concat_hashes[1], &hashes[i + 1][0], crypto_hash_sha512_BYTES);
      }

      res = crypto_hash_sha512(hashes[j], *concat_hashes,
                               2 * crypto_hash_sha512_BYTES);
      if (res != 0)
      {
        free(hashes);
        free(concat_hashes);

        return -3;
      }
    }

    if (leaves == 1) break;

    leaves = ceil((double)leaves / 2);
  }

  memcpy(root, *hashes, crypto_hash_sha512_BYTES);

  free(hashes);
  free(concat_hashes);

  return 0;
}
