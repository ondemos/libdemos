#include "utils.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

int
calculate_proof_len(const unsigned int IDENTITIES_LEN,
                    const unsigned int IDENTITY_INDEX_USED)
{
  return crypto_hash_sha512_BYTES
         + (IDENTITIES_LEN - IDENTITY_INDEX_USED + 1)
               * (crypto_sign_ed25519_PUBLICKEYBYTES
                  + crypto_auth_hmacsha512_KEYBYTES)
         + crypto_sign_ed25519_BYTES;
}
