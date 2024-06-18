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

  printf("INFO: Split secret data\n");

  uint8_t *restored = (uint8_t *)malloc(sizeof(uint8_t[DATA_LEN]));
  if (restored == NULL)
  {
    free(random_array);
    free(shares);

    printf("ERROR: Could not allocate space for restored secret\n");

    return -5;
  }

  res = restore_secret(SHARES_LEN, DATA_LEN, shares, restored);
  if (res != 0)
  {
    free(random_array);
    free(shares);
    free(restored);

    printf("ERROR: There was an error restoring the splitted secret %d\n", res);

    return -6;
  }

  printf("INFO: Produced a restored secret\n");

  for (size_t i = 0; i < DATA_LEN; i++)
  {
    if (restored[i] != random_array[i])
    {
      free(shares);
      free(restored);
      free(random_array);

      printf(
          "ERROR: Could not restore secret at index %zu, restored was %d while "
          "original was %d\n",
          i, restored[i], random_array[i]);

      return -7;
    }
  }

  printf("SUCCESS. Restored secret matches the splitted secret\n");

  uint8_t *coefficients
      = (uint8_t *)malloc(sizeof(uint8_t[DATA_LEN * THRESHOLD]));
  if (coefficients == NULL)
  {
    free(shares);
    free(restored);
    free(random_array);

    printf("ERROR: Could not allocate space for coefficients\n");

    return -8;
  }

  random_bytes(DATA_LEN * THRESHOLD, coefficients);

  printf("INFO: Allocated space for coefficients if we want to provide our own "
         "randomness");

  res = split_secret_with_randomness(SHARES_LEN, THRESHOLD, DATA_LEN,
                                     random_array, coefficients, shares);
  if (res != 0)
  {
    free(shares);
    free(restored);
    free(random_array);

    printf(
        "ERROR: There was an error splitting the random secret with provided "
        "randomness %d\n",
        res);

    return -9;
  }

  printf("INFO: Split secret data with provided randomness\n");

  res = restore_secret(SHARES_LEN, DATA_LEN, shares, restored);
  if (res != 0)
  {
    free(shares);
    free(restored);
    free(random_array);

    printf("ERROR: There was an error restoring the splitted secret %d\n", res);

    return -10;
  }

  printf("INFO: Produced a restored secret with provided randomness\n");

  res = memcmp(restored, random_array, DATA_LEN);

  free(shares);
  free(restored);
  free(random_array);

  if (res != 0)
  {
    printf("ERROR: Could not restore secret with provided randomness\n");

    return -11;
  }

  printf("SUCCESS. Restored secret matches the splitted secret with provided "
         "randomness\n");

  return 0;
}
