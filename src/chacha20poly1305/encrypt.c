#include "./chacha20poly1305.h"

/* Returns (public_key || nonce || encrypted_data || auth tag) */
int
encrypt_chachapoly(
    const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t receiver_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t sender_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const unsigned int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[ENCRYPTED_LEN(DATA_LEN)])
{
  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext = malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL) return -1;

  uint8_t *sender_x25519_pk = malloc(crypto_aead_chacha20poly1305_KEYBYTES);
  if (sender_x25519_pk == NULL)
  {
    free(ciphertext);

    return -2;
  }

  uint8_t *sender_x25519_sk
      = sodium_malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (sender_x25519_sk == NULL)
  {
    free(ciphertext);
    free(sender_x25519_pk);

    return -3;
  }

  int converted_sk = crypto_sign_ed25519_sk_to_curve25519(sender_x25519_sk,
                                                          sender_secret_key);
  if (converted_sk != 0)
  {
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -4;
  }

  crypto_scalarmult_curve25519_base(sender_x25519_pk, sender_x25519_sk);

  uint8_t *receiver_x25519_pk
      = malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (receiver_x25519_pk == NULL)
  {
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -5;
  }

  int converted_pk = crypto_sign_ed25519_pk_to_curve25519(receiver_x25519_pk,
                                                          receiver_public_key);
  if (converted_pk != 0)
  {
    free(receiver_x25519_pk);
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -6;
  }

  uint8_t *server_tx
      = sodium_malloc(sizeof(uint8_t[crypto_kx_SESSIONKEYBYTES]));
  if (server_tx == NULL)
  {
    free(receiver_x25519_pk);
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    free(ciphertext);

    return -7;
  }

  int created = crypto_kx_server_session_keys(
      NULL, server_tx, sender_x25519_pk, sender_x25519_sk, receiver_x25519_pk);
  // free(sender_x25519_pk);
  free(receiver_x25519_pk);
  sodium_free(sender_x25519_sk);
  if (created != 0)
  {
    free(sender_x25519_pk);
    sodium_free(server_tx);
    free(ciphertext);

    return -8;
  }

  uint8_t *nonce
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]));
  if (nonce == NULL)
  {
    free(sender_x25519_pk);
    sodium_free(server_tx);
    free(ciphertext);

    return -9;
  }

  memcpy(encrypted, sender_x25519_pk, crypto_scalarmult_curve25519_BYTES);
  free(sender_x25519_pk);

  calculate_nonce(nonce);
  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, server_tx);
  sodium_free(server_tx);

  memcpy(encrypted + crypto_scalarmult_curve25519_BYTES, nonce,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  free(nonce);

  int KEY_NONCE_LEN = crypto_scalarmult_curve25519_BYTES
                      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  memcpy(encrypted + KEY_NONCE_LEN, ciphertext, CIPHERTEXT_LEN);
  free(ciphertext);

  return 0;
}
