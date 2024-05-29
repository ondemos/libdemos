#include <string.h>

#include "utils.h"

#include "../../libsodium/src/libsodium/include/sodium/utils.h"

void
calculate_nonce(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES])
{
  uint8_t *nonce_random_vector
      = sodium_malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (nonce_random_vector != NULL)
  {
    random_bytes(crypto_hash_sha512_BYTES, nonce_random_vector);

    uint8_t *nonce_sha512 = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
    if (nonce_sha512 != NULL)
    {
      crypto_hash_sha512(nonce_sha512, nonce_random_vector,
                         crypto_hash_sha512_BYTES);
      sodium_free(nonce_random_vector);

      memcpy(nonce, nonce_sha512 + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
             crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
      free(nonce_sha512);
    }
    else
    {
      sodium_free(nonce_random_vector);
    }
  }
}
