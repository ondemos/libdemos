#pragma once

#ifndef DCOMMITT_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#define DCOMMITT_PUBLIC __declspec(dllimport)
#else
#define DCOMMITT_PUBLIC
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "../src/identities/identities.h"

#include "../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

  DCOMMITT_PUBLIC identity *new_identity(const unsigned int IDENTITIES_LEN,
                                         const unsigned int NONCE_LEN);

  DCOMMITT_PUBLIC void free_identity(identity *id);

  DCOMMITT_PUBLIC int populate_identity(
      const unsigned int IDENTITIES_LEN, const unsigned int NONCE_LEN,
      uint8_t nonces[IDENTITIES_LEN][NONCE_LEN],
      uint8_t public_keys[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES],
      uint8_t secret_keys[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES],
      uint8_t reversible_details[2 * crypto_hash_sha512_BYTES],
      uint8_t irreversible_details[crypto_hash_sha512_BYTES]);

  DCOMMITT_PUBLIC int commitment_update_reversible(
      uint8_t updatedCommit[crypto_hash_sha512_BYTES],
      const uint8_t previousCommit[crypto_hash_sha512_BYTES],
      const uint8_t reversibleCommitDetails[2 * crypto_hash_sha512_BYTES]);

  DCOMMITT_PUBLIC int commitment_update_irreversible(
      uint8_t updatedCommit[crypto_hash_sha512_BYTES],
      const uint8_t previousCommit[crypto_hash_sha512_BYTES],
      const uint8_t irreversibleCommitDetails[crypto_hash_sha512_BYTES]);

  DCOMMITT_PUBLIC int generate_ownership_proof(
      const unsigned int PROOF_LEN, const unsigned int IDENTITIES_LEN,
      const unsigned int NONCE_LEN,
      const uint8_t commitment[crypto_hash_sha512_BYTES],
      const uint8_t previous_commit[crypto_hash_sha512_BYTES],
      const uint8_t nonces[IDENTITIES_LEN][NONCE_LEN],
      const uint8_t public_keys[IDENTITIES_LEN]
                               [crypto_sign_ed25519_PUBLICKEYBYTES],
      const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
      uint8_t proof[PROOF_LEN]);

  DCOMMITT_PUBLIC int
  verify_ownership_proof(const unsigned int PROOF_LEN,
                         const uint8_t commitment[crypto_hash_sha512_BYTES],
                         const uint8_t proof[PROOF_LEN]);

#ifdef __cplusplus
}
#endif
