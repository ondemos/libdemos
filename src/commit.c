#include <stdlib.h>
#include <string.h>

#include "demos.h"

/**
 * Receives commit details and previous commit and then
 * outputs the new commit
 */
int
commit(uint8_t out[crypto_hash_sha512_BYTES],
       const uint8_t in[crypto_hash_sha512_BYTES],
       const uint8_t details[crypto_auth_hmacsha512_BYTES])
{
  uint8_t *concat_hashes
      = (uint8_t *)malloc(sizeof(uint8_t[2 * crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL) return -1;

  memcpy(concat_hashes, details, crypto_auth_hmacsha512_BYTES);

  // The second leaf of the Merkle tree is the previous commit
  memcpy(&concat_hashes[crypto_auth_hmacsha512_BYTES], in,
         crypto_hash_sha512_BYTES);

  // Use output_commitment is the hash of the concatenation
  int res
      = crypto_hash_sha512(out, concat_hashes, 2 * crypto_hash_sha512_BYTES);
  free(concat_hashes);

  if (res != 0) return -2;

  return 0;
}
