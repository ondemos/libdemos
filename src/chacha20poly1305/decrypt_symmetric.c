#include "chacha20poly1305.h"

int
decrypt_chachapoly_symmetric(
    const unsigned int ENCRYPTED_LEN,
    const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long DATA_LEN = ENCRYPTED_LEN
                                - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                                - crypto_aead_chacha20poly1305_ietf_ABYTES;

  uint8_t *nonce
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]));
  if (nonce == NULL) return -1;

  memcpy(nonce, encrypted_data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  int CIPHERTEXT_LEN
      = ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  uint8_t *ciphertext = malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL)
  {
    free(nonce);

    return -2;
  }

  memcpy(ciphertext,
         encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
         CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, nonce, key);

  free(ciphertext);
  free(nonce);

  if (decrypted == 0) return 0;

  return -3;
}
