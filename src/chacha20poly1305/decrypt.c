#include "./chacha20poly1305.h"

int
decrypt_chachapoly(
    const unsigned int ENCRYPTED_LEN,
    const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[DECRYPTED_LEN(ENCRYPTED_LEN)])
{
  int EPHEMERAL_NONCE_LEN = crypto_scalarmult_curve25519_BYTES
                            + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

  unsigned long long DATA_LEN = ENCRYPTED_LEN - EPHEMERAL_NONCE_LEN
                                - crypto_aead_chacha20poly1305_ietf_ABYTES
                                - crypto_sign_ed25519_BYTES;

  uint8_t *ephemeral_x25519_pk
      = malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (ephemeral_x25519_pk == NULL) return -1;

  memcpy(ephemeral_x25519_pk, encrypted_data,
         crypto_scalarmult_curve25519_BYTES);

  uint8_t *nonce
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]));
  if (nonce == NULL)
  {
    free(ephemeral_x25519_pk);

    return -2;
  }

  memcpy(nonce, encrypted_data + crypto_scalarmult_curve25519_BYTES,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  uint8_t *x25519_pk
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_KEYBYTES]));
  if (x25519_pk == NULL)
  {
    free(ephemeral_x25519_pk);
    free(nonce);

    return -3;
  }

  uint8_t *x25519_sk
      = sodium_malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (x25519_sk == NULL)
  {
    free(ephemeral_x25519_pk);
    free(nonce);
    free(x25519_pk);

    return -4;
  }

  crypto_sign_ed25519_sk_to_curve25519(x25519_sk, receiver_secret_key);
  crypto_scalarmult_curve25519_base(x25519_pk, x25519_sk);

  uint8_t *client_rx
      = sodium_malloc(sizeof(uint8_t[crypto_kx_SESSIONKEYBYTES]));
  if (client_rx == NULL)
  {
    free(ephemeral_x25519_pk);
    free(nonce);
    free(x25519_pk);
    sodium_free(x25519_sk);

    return -5;
  }

  int created = crypto_kx_client_session_keys(client_rx, NULL, x25519_pk,
                                              x25519_sk, ephemeral_x25519_pk);
  free(x25519_pk);
  sodium_free(x25519_sk);
  free(ephemeral_x25519_pk);
  if (created != 0)
  {
    free(nonce);
    sodium_free(client_rx);

    return -6;
  }

  int CIPHERTEXT_LEN = ENCRYPTED_LEN - EPHEMERAL_NONCE_LEN;
  uint8_t *ciphertext = malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL)
  {
    free(nonce);
    sodium_free(client_rx);

    return -7;
  }

  memcpy(ciphertext, encrypted_data + EPHEMERAL_NONCE_LEN, CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, nonce, client_rx);

  free(ciphertext);
  sodium_free(client_rx);
  free(nonce);

  if (decrypted == 0) return 0;

  return -8;
}
