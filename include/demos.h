#pragma once

#ifndef DEMOS_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#define DEMOS_PUBLIC __declspec(dllimport)
#else
#define DEMOS_PUBLIC
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include "../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

  DEMOS_PUBLIC int random_bytes(const unsigned int SIZE, uint8_t array[SIZE]);

  DEMOS_PUBLIC int random_number_in_range(const int MIN, const int MAX);

  DEMOS_PUBLIC int sha512(const unsigned int DATA_LEN,
                          const uint8_t data[DATA_LEN],
                          uint8_t hash[crypto_hash_sha512_BYTES]);

  DEMOS_PUBLIC int argon2(const unsigned int MNEMONIC_LEN,
                          uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
                          const char mnemonic[MNEMONIC_LEN],
                          const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES]);

  DEMOS_PUBLIC int
  keypair(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
          uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

  DEMOS_PUBLIC int
  keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                    uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                    const uint8_t seed[crypto_sign_ed25519_SEEDBYTES]);

  DEMOS_PUBLIC int keypair_from_secret_key(
      uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
      const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);

  DEMOS_PUBLIC int
  sign(const int DATA_LEN, const uint8_t data[DATA_LEN],
       const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
       uint8_t signature[crypto_sign_ed25519_BYTES]);

  DEMOS_PUBLIC int
  verify(const int DATA_LEN, const uint8_t data[DATA_LEN],
         const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
         const uint8_t signature[crypto_sign_ed25519_BYTES]);

  DEMOS_PUBLIC int encrypt_chachapoly_asymmetric(
      const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
      const uint8_t receiver_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
      const uint8_t sender_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
      const unsigned int ADDITIONAL_DATA_LEN,
      const uint8_t additional_data[ADDITIONAL_DATA_LEN],
      uint8_t encrypted[crypto_scalarmult_curve25519_BYTES
                        + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                        + crypto_aead_chacha20poly1305_ietf_ABYTES]);

  DEMOS_PUBLIC int decrypt_chachapoly_asymmetric(
      const unsigned int ENCRYPTED_LEN,
      const uint8_t encrypted_data[ENCRYPTED_LEN],
      const uint8_t receiver_secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
      const unsigned int ADDITIONAL_DATA_LEN,
      const uint8_t additional_data[ADDITIONAL_DATA_LEN],
      uint8_t data[ENCRYPTED_LEN - crypto_scalarmult_curve25519_BYTES
                   - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                   - crypto_aead_chacha20poly1305_ietf_ABYTES]);

  DEMOS_PUBLIC
  int encrypt_chachapoly_symmetric(
      const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
      const uint8_t key[crypto_kx_SESSIONKEYBYTES],
      const unsigned int ADDITIONAL_DATA_LEN,
      const uint8_t additional_data[ADDITIONAL_DATA_LEN],
      uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                        + crypto_aead_chacha20poly1305_ietf_ABYTES]);

  DEMOS_PUBLIC
  int decrypt_chachapoly_symmetric(
      const unsigned int ENCRYPTED_LEN,
      const uint8_t encrypted_data[ENCRYPTED_LEN],
      const uint8_t key[crypto_kx_SESSIONKEYBYTES],
      const unsigned int ADDITIONAL_DATA_LEN,
      const uint8_t additional_data[ADDITIONAL_DATA_LEN],
      uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                   - crypto_aead_chacha20poly1305_ietf_ABYTES]);

  DEMOS_PUBLIC int generate_identities(
      const unsigned int IDENTITIES_LEN,
      uint8_t nonces[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES],
      uint8_t public_keys[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES],
      uint8_t secret_keys[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES],
      uint8_t commit_details[crypto_auth_hmacsha512_BYTES]);

  DEMOS_PUBLIC int commit(uint8_t out[crypto_hash_sha512_BYTES],
                          const uint8_t in[crypto_hash_sha512_BYTES],
                          const uint8_t details[crypto_auth_hmacsha512_BYTES]);

  DEMOS_PUBLIC int generate_proof(
      const unsigned int PROOF_LEN, const unsigned int IDENTITIES_LEN,
      const uint8_t current_commit[crypto_hash_sha512_BYTES],
      const uint8_t previous_commit[crypto_hash_sha512_BYTES],
      const uint8_t nonces[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES],
      const uint8_t public_keys[IDENTITIES_LEN]
                               [crypto_sign_ed25519_PUBLICKEYBYTES],
      const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
      uint8_t proof[PROOF_LEN]);

  DEMOS_PUBLIC int
  verify_proof(const unsigned int PROOF_LEN,
               const uint8_t current_commit[crypto_hash_sha512_BYTES],
               const uint8_t proof[PROOF_LEN]);

  DEMOS_PUBLIC int get_merkle_proof(
      const unsigned int LEAVES_LEN,
      const uint8_t leaves_hashed[LEAVES_LEN][crypto_hash_sha512_BYTES],
      const uint8_t element_hash[crypto_hash_sha512_BYTES],
      uint8_t proof[LEAVES_LEN][crypto_hash_sha512_BYTES + 1]);

  DEMOS_PUBLIC int get_merkle_root(
      const unsigned int LEAVES_LEN,
      const uint8_t leaves_hashed[LEAVES_LEN][crypto_hash_sha512_BYTES],
      uint8_t root[crypto_hash_sha512_BYTES]);

  DEMOS_PUBLIC int get_merkle_root_from_proof(
      const unsigned int PROOF_ARTIFACTS_LEN,
      const uint8_t element_hash[crypto_hash_sha512_BYTES],
      const uint8_t proof[PROOF_ARTIFACTS_LEN][crypto_hash_sha512_BYTES + 1],
      uint8_t root[crypto_hash_sha512_BYTES]);

  DEMOS_PUBLIC int verify_merkle_proof(
      const unsigned int PROOF_ARTIFACTS_LEN,
      const uint8_t element_hash[crypto_hash_sha512_BYTES],
      const uint8_t root[crypto_hash_sha512_BYTES],
      const uint8_t proof[PROOF_ARTIFACTS_LEN][crypto_hash_sha512_BYTES + 1]);

  DEMOS_PUBLIC int split_secret(const unsigned int SHARES_LEN,
                                const unsigned int THRESHOLD,
                                const unsigned int SECRET_LEN,
                                const uint8_t secret[SECRET_LEN],
                                uint8_t shares[SHARES_LEN][SECRET_LEN + 1]);

  DEMOS_PUBLIC int
  restore_secret(const unsigned int SHARES_LEN, const unsigned int SECRET_LEN,
                 const uint8_t shares[SHARES_LEN][SECRET_LEN + 1],
                 uint8_t secret[SECRET_LEN]);

#ifdef __cplusplus
}
#endif
