#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/demos.h"

int
main()
{
  int res;

  const unsigned int IDENTITIES_LEN = 14;

  uint8_t *nonces = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_auth_hmacsha512_KEYBYTES]));
  if (nonces == NULL)
  {
    printf("ERROR: Could not allocate space for nonces\n");

    return -1;
  }

  printf("INFO: Allocated space for nonces\n");

  uint8_t *public_keys = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (public_keys == NULL)
  {
    printf("ERROR: Could not allocate space for public keys\n");
    free(nonces);

    return -2;
  }

  printf("INFO: Allocated space for public keys\n");

  uint8_t *secret_keys = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_sign_ed25519_SECRETKEYBYTES]));
  if (secret_keys == NULL)
  {
    free(nonces);
    free(public_keys);

    printf("ERROR: Could not allocate space for secret keys\n");

    return -3;
  }

  printf("INFO: Allocated space for secret keys\n");

  res = generate_identities(IDENTITIES_LEN, nonces, public_keys, secret_keys);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);

    printf("ERROR: Could not generate identities\n");

    return -4;
  }

  printf("INFO: Generated identities\n");

  uint8_t *commit_details
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (commit_details == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);

    printf("ERROR: Could not allocate space for commit details\n");

    return -5;
  }

  printf("INFO: Allocated space for commit details\n");

  res = generate_commit_details(IDENTITIES_LEN, nonces, public_keys,
                                commit_details);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    printf("ERROR: Could not generate commit details\n");

    return -6;
  }

  printf("INFO: Generated commit details\n");

  uint8_t *current_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (current_commit == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    printf("ERROR: Could allocate space for initial commit\n");

    return -7;
  }

  printf("INFO: Allocated space for current commit\n");

  uint8_t *initial_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (initial_commit == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);
    free(current_commit);

    printf("ERROR: Could allocate space for initial commit\n");

    return -8;
  }

  printf("INFO: Allocated space for initial commit\n");

  random_bytes(crypto_hash_sha512_BYTES, initial_commit);

  res = commit(current_commit, initial_commit, commit_details);
  free(commit_details);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not reversibly update the initial commit\n");

    return -9;
  }

  const unsigned int IDENTITY_INDEX_USED = IDENTITIES_LEN - 2;

  const unsigned int PROOF_LEN = crypto_hash_sha512_BYTES
                                 + (IDENTITIES_LEN - IDENTITY_INDEX_USED)
                                       * (crypto_sign_ed25519_PUBLICKEYBYTES
                                          + crypto_auth_hmacsha512_KEYBYTES)
                                 + crypto_sign_ed25519_BYTES;
  uint8_t *proof = (uint8_t *)malloc(sizeof(uint8_t[PROOF_LEN]));
  if (proof == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not allocate commitment proof\n");

    return -10;
  }

  printf("INFO: Allocated proof\n");

  res = generate_proof(
      PROOF_LEN, IDENTITIES_LEN, current_commit, initial_commit, nonces,
      public_keys,
      secret_keys + IDENTITY_INDEX_USED * crypto_sign_ed25519_SECRETKEYBYTES,
      proof);
  if (res != 0)
  {
    free(proof);
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not generate ownership proof %d\n", res);

    return -11;
  }

  printf("INFO: Generated ownership proof\n");

  res = verify_proof(PROOF_LEN, current_commit, proof);

  free(proof);
  free(nonces);
  free(public_keys);
  free(secret_keys);
  free(initial_commit);
  free(current_commit);

  if (res < 0)
  {
    printf("ERROR: Proof verification is wrong %d\n", res);

    return -15 + res;
  }

  printf("SUCCESS. Identity's distance from commit was %i\n", res);

  return 0;
}
