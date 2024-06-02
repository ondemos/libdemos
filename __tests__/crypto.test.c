#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/demos.h"
#include "../libsodium/src/libsodium/include/sodium/utils.h"

int
main()
{
  const unsigned int DATA_LEN = crypto_sign_ed25519_SEEDBYTES;
  uint8_t *random_array = (uint8_t *)malloc(sizeof(uint8_t[DATA_LEN]));
  if (random_array == NULL)
  {
    printf("Could not allocate random array\n");

    return -1;
  }

  int res = random_bytes(DATA_LEN, random_array);
  if (res != 0)
  {
    free(random_array);

    printf("Could not generate random data\n");

    return -2;
  }

  uint8_t *hash = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(random_array);

    printf("Could not allocate space for hash\n");

    return -3;
  }

  res = sha512(DATA_LEN, random_array, hash);
  if (res != 0)
  {
    free(random_array);
    free(hash);

    printf("Could not calculate SHA512 hash of data\n");

    return -4;
  }

  printf("Hashed some random data\n");

  uint8_t *ed25519_pk
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (ed25519_pk == NULL)
  {
    free(random_array);
    free(hash);

    printf("Could not allocate space for ed25519 public key\n");

    return -5;
  }

  uint8_t *ed25519_sk = (uint8_t *)sodium_malloc(
      sizeof(uint8_t[crypto_sign_ed25519_SECRETKEYBYTES]));
  if (ed25519_sk == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);

    printf("Could not allocate space for ed25519 secret key\n");

    return -6;
  }

  res = keypair(ed25519_pk, ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not generate Ed25519 keypair from new_keypair function\n");

    return -7;
  }

  res = keypair_from_seed(ed25519_pk, ed25519_sk, random_array);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf(
        "Could not generate Ed25519 keypair from keypair_from_seed function\n");

    return -8;
  }

  res = keypair_from_secret_key(ed25519_pk, ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not generate Ed25519 keypair from keypair_from_secret_key "
           "function\n");

    return -9;
  }

  printf("Generated ed25519 keypair\n");

  uint8_t *sig = (uint8_t *)malloc(sizeof(uint8_t[crypto_sign_ed25519_BYTES]));
  if (sig == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not allocate space for ed25519 signature\n");

    return -10;
  }

  res = sign(DATA_LEN, random_array, ed25519_sk, sig);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(sig);

    printf("Could not generate Ed25519 signature\n");

    return -11;
  }

  int verified = verify(DATA_LEN, random_array, ed25519_pk, sig);
  free(sig);
  if (verified != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not verify signed data\n");

    return -12;
  }

  printf("Signed and verified data\n");

  uint8_t *another_ed25519_pk
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (another_ed25519_pk == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not allocate space for another ed25519 public key\n");

    return -13;
  }

  uint8_t *another_ed25519_sk = (uint8_t *)sodium_malloc(
      sizeof(uint8_t[crypto_sign_ed25519_SECRETKEYBYTES]));
  if (another_ed25519_sk == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(another_ed25519_pk);

    printf("Could not allocate space for another ed25519 secret key\n");

    return -14;
  }

  res = crypto_sign_ed25519_keypair(another_ed25519_pk, another_ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);

    printf("Could not generate another ed25519 keypair\n");

    return -15;
  }

  int ENCRYPTED_LEN = crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *encrypted = (uint8_t *)malloc(sizeof(uint8_t[ENCRYPTED_LEN]));
  if (encrypted == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);

    printf("Could not allocate space for asymmetric encrypted data\n");

    return -16;
  }

  res = encrypt_chachapoly_asymmetric(
      DATA_LEN, random_array, another_ed25519_pk, ed25519_sk,
      crypto_hash_sha512_BYTES, hash, encrypted);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);
    free(encrypted);

    printf("Could not encrypt random data with asymmetric chachapoly\n");

    return -17;
  }

  uint8_t *decrypted = (uint8_t *)malloc(sizeof(uint8_t[DATA_LEN]));
  if (decrypted == NULL)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);
    free(encrypted);

    printf("Could not allocate space for decrypted data\n");

    return -18;
  }

  res = decrypt_chachapoly_asymmetric(
      ENCRYPTED_LEN, encrypted, ed25519_pk, another_ed25519_sk,
      crypto_hash_sha512_BYTES, hash, decrypted);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);
    free(encrypted);
    free(decrypted);

    printf("Could not decrypt encrypted data\n");

    return -19;
  }

  printf("Encrypted and decrypted data\n");

  free(hash);
  free(ed25519_pk);
  sodium_free(ed25519_sk);

  free(another_ed25519_pk);
  sodium_free(another_ed25519_sk);
  free(encrypted);

  for (size_t i = 0; i < DATA_LEN; i++)
  {
    if (decrypted[i] != random_array[i])
    {
      free(random_array);
      free(decrypted);

      printf("Could not decrypt secret at index %zu, decrypted was %d while "
             "original was %d\n",
             i, decrypted[i], random_array[i]);

      return -20;
    }
  }

  free(random_array);
  free(decrypted);

  printf("SUCCESS. Hashed, signed and encrypted decrypted successfully a "
         "random array\n");

  return 0;
}
