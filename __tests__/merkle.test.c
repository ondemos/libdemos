#include <_types/_uint8_t.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/demos.h"

int
main()
{
  const unsigned int DATA_LEN = crypto_sign_ed25519_SEEDBYTES;
  const unsigned int SHARES_LEN = 255;
  const unsigned int THRESHOLD = 101;

  uint8_t *random_array = (uint8_t *)malloc(sizeof(uint8_t[DATA_LEN]));
  if (random_array == NULL)
  {
    printf("ERROR: Could not allocate random data to split\n");

    return -1;
  }

  int res = random_bytes(DATA_LEN, random_array);
  if (res != 0)
  {
    free(random_array);

    printf("ERROR: Could not generate random data\n");

    return -2;
  }

  uint8_t *shares
      = (uint8_t *)malloc(sizeof(uint8_t[SHARES_LEN * (DATA_LEN + 1)]));
  if (shares == NULL)
  {
    free(random_array);

    printf("ERROR: Could not allocate space for shares\n");

    return -3;
  }

  res = split_secret(SHARES_LEN, THRESHOLD, DATA_LEN, random_array, shares);
  if (res != 0)
  {
    free(random_array);
    free(shares);

    printf("ERROR: There was an error splitting the random secret %d\n", res);

    return -4;
  }

  printf("INFO: Generated split secret data\n");

  free(random_array);

  uint8_t *merkle_leaves = (uint8_t *)malloc(
      sizeof(uint8_t[SHARES_LEN * crypto_hash_sha512_BYTES]));
  if (merkle_leaves == NULL)
  {
    free(shares);

    printf("ERROR: Could not allocate space for merkle tree leaves\n");

    return -5;
  }

  uint8_t *leaf_hash
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (leaf_hash == NULL)
  {
    free(shares);
    free(merkle_leaves);

    printf("ERROR: Could not allocate space for merkle tree leaf hash\n");

    return -6;
  }

  for (size_t i = 0; i < SHARES_LEN; i++)
  {
    res = sha512(DATA_LEN + 1, &shares[i * (DATA_LEN + 1)], leaf_hash);
    if (res != 0)
    {
      free(shares);
      free(merkle_leaves);
      free(leaf_hash);

      printf("ERROR: Could not calculate SHA512 hash of each share\n");

      return -7;
    }

    memcpy(&merkle_leaves[i * crypto_hash_sha512_BYTES], leaf_hash,
           crypto_hash_sha512_BYTES);
  }

  free(shares);
  free(leaf_hash);

  uint8_t *merkle_root
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (merkle_root == NULL)
  {
    free(merkle_leaves);

    printf("ERROR: Could not allocate space for merkle root\n");

    return -8;
  }

  res = get_merkle_root(SHARES_LEN, merkle_leaves, merkle_root);
  if (res != 0)
  {
    free(merkle_leaves);
    free(merkle_root);

    printf("ERROR: Could not calculate Merkle root of shares\n");

    return -9;
  }

  printf("INFO: Calculated merkle root of shamir shares\n");

  size_t leaf_index = 128; // SHARES_LEN - 63;

  uint8_t *merkle_proof_full = (uint8_t *)malloc(
      sizeof(uint8_t[SHARES_LEN * (crypto_hash_sha512_BYTES + 1)]));
  if (merkle_proof_full == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);

    printf("ERROR: Could not allocate space for merkle proof full\n");

    return -10;
  }

  res = get_merkle_proof(SHARES_LEN, merkle_leaves,
                         &merkle_leaves[leaf_index * crypto_hash_sha512_BYTES],
                         merkle_proof_full);
  if (res < 0)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_full);

    printf("ERROR: Could not calculate merkle proof of last share. Result was "
           "%d\n",
           res);

    return -11;
  }

  printf("INFO: Got merkle proof of item 128\n");

  unsigned int PROOF_ARTIFACTS_LEN = res / (crypto_hash_sha512_BYTES + 1);

  uint8_t *merkle_proof = (uint8_t *)malloc(
      sizeof(uint8_t[PROOF_ARTIFACTS_LEN * (crypto_hash_sha512_BYTES + 1)]));
  if (merkle_proof == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_full);

    printf("ERROR: Could not allocate space for merkle proof\n");

    return -12;
  }

  memcpy(merkle_proof, merkle_proof_full, res);
  free(merkle_proof_full);

  res = verify_merkle_proof(
      PROOF_ARTIFACTS_LEN,
      &merkle_leaves[leaf_index * crypto_hash_sha512_BYTES], merkle_root,
      merkle_proof);
  if (res != 0)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof);

    printf("ERROR: Could not verify merkle proof 1. Result was %d\n", res);

    return -12;
  }

  printf("INFO: Verified merkle proof of shamir share number 128 from root\n");

  uint8_t *merkle_root_verification
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (merkle_root_verification == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof);

    printf("ERROR: Could not allocate space for merkle root verification\n");

    return -13;
  }

  res = get_merkle_root_from_proof(
      PROOF_ARTIFACTS_LEN,
      &merkle_leaves[leaf_index * crypto_hash_sha512_BYTES], merkle_proof,
      merkle_root_verification);
  if (res != 0)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof);
    free(merkle_root_verification);

    printf(
        "ERROR: Could not get merkle root from merkle proof. Result was %d\n",
        res);

    return -14;
  }

  for (size_t j = 0; j < crypto_hash_sha512_BYTES; j++)
  {
    if (merkle_root_verification[j] != merkle_root[j])
    {
      free(merkle_leaves);
      free(merkle_proof);

      printf("ERROR: Merkle root element in position %zu is %d and "
             "verification %d\n",
             j, merkle_root[j], merkle_root_verification[j]);

      free(merkle_root);
      free(merkle_root_verification);

      printf("ERROR: Could not recreate merkle root from proof\n");

      return -15;
    }
  }

  free(merkle_proof);
  free(merkle_root_verification);

  printf("INFO: Calculated merkle root from proof of item 128\n");

  // For double check
  uint8_t *merkle_proof_full_1 = (uint8_t *)malloc(
      sizeof(uint8_t[SHARES_LEN * (crypto_hash_sha512_BYTES + 1)]));
  if (merkle_proof_full_1 == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);

    printf("ERROR: Could not allocate space for another merkle proof full\n");

    return -15;
  }

  res = get_merkle_proof(
      SHARES_LEN, merkle_leaves,
      &merkle_leaves[(leaf_index + 1) * crypto_hash_sha512_BYTES],
      merkle_proof_full_1);
  if (res < 0)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_full_1);

    printf("ERROR: Could not get merkle proof. Result was %d\n", res);

    return -16;
  }

  printf("INFO: Calculated merkle proof of share number 129\n");

  unsigned int PROOF_ARTIFACTS_LEN_2 = res / (crypto_hash_sha512_BYTES + 1);
  uint8_t *merkle_proof_1 = (uint8_t *)malloc(
      sizeof(uint8_t[PROOF_ARTIFACTS_LEN_2 * (crypto_hash_sha512_BYTES + 1)]));
  if (merkle_proof_1 == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_full_1);

    printf("ERROR: Could not allocate space for another merkle proof\n");

    return -17;
  }

  memcpy(merkle_proof_1, merkle_proof_full_1, res);
  free(merkle_proof_full_1);

  uint8_t *merkle_root_verification_1
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (merkle_root_verification_1 == NULL)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_1);

    printf("ERROR: Could not allocate space for another merkle root "
           "verification\n");

    return -18;
  }

  res = get_merkle_root_from_proof(
      PROOF_ARTIFACTS_LEN_2,
      &merkle_leaves[(leaf_index + 1) * crypto_hash_sha512_BYTES],
      merkle_proof_1, merkle_root_verification_1);
  if (res != 0)
  {
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_1);
    free(merkle_root_verification_1);

    printf("ERROR: Could not get merkle root from proof. Result was %d\n", res);

    return -19;
  }

  for (size_t j = 0; j < crypto_hash_sha512_BYTES; j++)
  {
    if (merkle_root_verification[j] != merkle_root_verification_1[j])
    {
      free(merkle_leaves);

      printf(
          "ERROR: Merkle root element in verification position %zu is %d and "
          "verification_1 is  %d\n",
          j, merkle_root[j], merkle_root_verification_1[j]);

      free(merkle_root);
      free(merkle_proof_1);
      free(merkle_root_verification_1);

      printf("ERROR: Could not recreate merkle root from proof\n");

      return -20;
    }
  }
  free(merkle_root_verification_1);

  res = verify_merkle_proof(
      PROOF_ARTIFACTS_LEN,
      &merkle_leaves[(leaf_index + 1) * crypto_hash_sha512_BYTES], merkle_root,
      merkle_proof_1);
  free(merkle_leaves);
  free(merkle_root);
  free(merkle_proof_1);
  if (res != 0)
  {
    printf("ERROR: Could not verify merkle proof 2. Result was %d\n", res);

    return -22;
  }

  printf("SUCCESS. Calculated, prooved and verified Merkle roots\n");

  return 0;
}
