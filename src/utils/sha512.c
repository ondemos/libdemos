#include "./utils.h"

int
sha512(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
       uint8_t hash[crypto_hash_sha512_BYTES])
{
  return crypto_hash_sha512(hash, data, DATA_LEN);
}
