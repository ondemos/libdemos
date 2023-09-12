#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/dcommitt.h"

#include "../libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
#include "../libsodium/src/libsodium/sodium/runtime.c"

int
main()
{
  int res;

  const unsigned int IDENTITIES_LEN = 14;
  const unsigned int NONCE_LEN = 12;

  identity *id = new_identity(IDENTITIES_LEN, NONCE_LEN);
  if (id == NULL)
  {
    printf("Could not generate identities\n");

    return -1;
  }

  // res = populate_identity(id->IDENTITIES_LEN, id->NONCE_LEN,
  //                         (uint8_t(*)[NONCE_LEN])id->nonces, id->public_keys,
  //                         id->secret_keys, id->reversible_commit_details,
  //                         id->irreversible_commit_details);

  // if (res != 0)
  // {
  //   free_identity(id);

  //   printf("Could not generate commit details\n");

  //   return -2;
  // }

  const unsigned int COMMIT_LEN = crypto_hash_sha512_BYTES;
  uint8_t *initial_commit = malloc(sizeof(uint8_t[COMMIT_LEN]));

  randombytes_buf(initial_commit, COMMIT_LEN);

  uint8_t *new_commit = malloc(sizeof(uint8_t[COMMIT_LEN]));
  if (new_commit == NULL)
  {
    free(initial_commit);
    free_identity(id);

    printf("Could not allocate new commit\n");

    return -3;
  }

  res = commitment_update_reversible(new_commit, initial_commit,
                                     id->reversible_commit_details);
  if (res != 0)
  {
    free(initial_commit);
    free(new_commit);
    free_identity(id);

    printf("Could not reversibly update the commit\n");

    return -4;
  }

  res = commitment_update_irreversible(new_commit, initial_commit,
                                       id->irreversible_commit_details);
  if (res != 0)
  {
    free(initial_commit);
    free(new_commit);
    free_identity(id);

    printf("Could not irreversibly update the commit\n");

    return -5;
  }

  const unsigned int PROOF_LEN
      = (1 + id->IDENTITIES_LEN) * crypto_hash_sha512_BYTES + 2 * 4
        + crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES;
  uint8_t *proof = malloc(sizeof(uint8_t[PROOF_LEN]));
  if (proof == NULL)
  {
    free(initial_commit);
    free(new_commit);
    free_identity(id);

    printf("Could not allocate commitment proof\n");

    return -6;
  }

  res = generate_ownership_proof(
      PROOF_LEN, id->IDENTITIES_LEN, id->NONCE_LEN, new_commit, initial_commit,
      (uint8_t(*)[NONCE_LEN])id->nonces, id->public_keys,
      id->secret_keys[IDENTITIES_LEN - 1], proof);
  if (res != 0)
  {
    free(proof);
    free(initial_commit);
    free(new_commit);
    free_identity(id);

    printf("Could not generate ownership proof\n");

    return -7;
  }

  res = verify_ownership_proof(PROOF_LEN, new_commit, proof);

  free(proof);
  free(initial_commit);
  free(new_commit);
  free_identity(id);

  if (res < 0)
  {
    printf("Proof verification is wrong\n");

    return -8;
  }

  printf("SUCCESS. Identity's distance from commit was %i\n", res);

  return 0;
}
