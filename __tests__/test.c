#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/demos.h"

int
main()
{
  int res;

  const unsigned int IDENTITIES_LEN = 14;

  uint8_t(*nonces)[crypto_auth_hmacsha512_KEYBYTES] = malloc(
      sizeof(uint8_t[IDENTITIES_LEN][crypto_auth_hmacsha512_KEYBYTES]));
  if (nonces == NULL)
  {
    printf("Could not allocate space for nonces\n");

    return -1;
  }

  printf("Allocated space for nonces\n");

  uint8_t(*public_keys)[crypto_sign_ed25519_PUBLICKEYBYTES] = malloc(
      sizeof(uint8_t[IDENTITIES_LEN][crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (public_keys == NULL)
  {
    printf("Could not allocate space for public keys\n");
    free(nonces);

    return -2;
  }

  printf("Allocated space for public keys\n");

  uint8_t(*secret_keys)[crypto_sign_ed25519_SECRETKEYBYTES] = malloc(
      sizeof(uint8_t[IDENTITIES_LEN][crypto_sign_ed25519_SECRETKEYBYTES]));
  if (secret_keys == NULL)
  {
    printf("Could not allocate space for secret keys\n");
    free(nonces);
    free(public_keys);

    return -3;
  }

  printf("Allocated space for secret keys\n");

  uint8_t *commit_details
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (commit_details == NULL)
  {
    printf("Could not allocate space for commit details\n");
    free(nonces);
    free(public_keys);
    free(secret_keys);

    return -5;
  }

  printf("Allocated space for external commit details\n");

  res = generate_identities(IDENTITIES_LEN, nonces, public_keys, secret_keys,
                            commit_details);
  if (res != 0)
  {
    printf("Could not generate identities\n");
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    return -6;
  }

  printf("Generated identities\n");

  uint8_t *current_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (current_commit == NULL)
  {
    printf("Could allocate space for initial commit\n");
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    return -7;
  }

  printf("Allocated space for current commit\n");

  uint8_t *initial_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (initial_commit == NULL)
  {
    printf("Could allocate space for initial commit\n");
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);
    free(current_commit);

    return -8;
  }

  printf("Allocated space for initial commit\n");

  random_bytes(crypto_hash_sha512_BYTES, initial_commit);

  res = commit(current_commit, initial_commit, commit_details);
  free(commit_details);
  if (res != 0)
  {
    printf("Could not reversibly update the initial commit\n");
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

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
    printf("Could not allocate commitment proof\n");

    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    return -10;
  }

  res = generate_proof(PROOF_LEN, IDENTITIES_LEN, current_commit,
                       initial_commit, nonces, public_keys,
                       secret_keys[IDENTITY_INDEX_USED], proof);
  if (res != 0)
  {
    printf("Could not generate ownership proof %d\n", res);

    free(proof);
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    return -11;
  }

  printf("Generated ownership proof\n");

  res = verify_proof(PROOF_LEN, current_commit, proof);

  free(proof);
  free(nonces);
  free(public_keys);
  free(secret_keys);
  free(initial_commit);
  free(current_commit);

  if (res < 0)
  {
    printf("Proof verification is wrong %d\n", res);

    return -15 + res;
  }

  printf("SUCCESS. Identity's distance from commit was %i\n", res);

  return 0;
}
