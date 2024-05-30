#include "chacha20poly1305.h"

/* Returns (nonce || encrypted_data || auth tag) */
int
encrypt_chachapoly_symmetric(
    const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext
      = (uint8_t *)sodium_malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL) return -1;

  uint8_t *nonce = (uint8_t *)malloc(
      sizeof(uint8_t[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]));
  if (nonce == NULL)
  {
    free(ciphertext);

    return -2;
  }

  calculate_nonce(nonce);

  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, key);

  memcpy(encrypted, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  free(nonce);

  memcpy(encrypted + crypto_aead_chacha20poly1305_ietf_NPUBBYTES, ciphertext,
         CIPHERTEXT_LEN);
  sodium_free(ciphertext);

  return 0;
}
