#include <stdint.h>
#include <string.h>

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

int
commitment_update_reversible(
    uint8_t updatedCommit[crypto_hash_sha512_BYTES],
    const uint8_t previousCommit[crypto_hash_sha512_BYTES],
    const uint8_t reversibleCommitDetails[2 * crypto_hash_sha512_BYTES])
{
  const unsigned int len = 2 * crypto_hash_sha512_BYTES;

  int res = crypto_hash_sha512(updatedCommit, reversibleCommitDetails, len);
  if (res != 0) return -1;

  uint8_t *concat_hashes = malloc(sizeof(uint8_t[len]));
  if (concat_hashes == NULL) return -2;

  memcpy(concat_hashes, updatedCommit, crypto_hash_sha512_BYTES);
  memcpy(&concat_hashes[crypto_hash_sha512_BYTES], previousCommit,
         crypto_hash_sha512_BYTES);

  res = crypto_hash_sha512(updatedCommit, concat_hashes, len);

  free(concat_hashes);

  if (res != 0) return -3;

  return 0;
}

int
commitment_update_irreversible(
    uint8_t updatedCommit[crypto_hash_sha512_BYTES],
    const uint8_t previousCommit[crypto_hash_sha512_BYTES],
    const uint8_t irreversibleCommitDetails[crypto_hash_sha512_BYTES])
{
  const unsigned int len = 2 * crypto_hash_sha512_BYTES;
  uint8_t *concat_hashes = malloc(sizeof(uint8_t[len]));
  if (concat_hashes == NULL) return -1;

  memcpy(concat_hashes, irreversibleCommitDetails, crypto_hash_sha512_BYTES);
  memcpy(&concat_hashes[crypto_hash_sha512_BYTES], previousCommit,
         crypto_hash_sha512_BYTES);

  int res = crypto_hash_sha512(updatedCommit, concat_hashes, len);

  free(concat_hashes);

  if (res != 0) return -2;

  return 0;
}
