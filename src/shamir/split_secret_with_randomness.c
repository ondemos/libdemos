#include <stdlib.h>

#include "../utils/utils.h"
#include "shamir.h"

int
split_secret_with_randomness(const unsigned int SHARES_LEN,
                             const unsigned int THRESHOLD,
                             const unsigned int SECRET_LEN,
                             const uint8_t secret[SECRET_LEN],
                             uint8_t coefficients[SECRET_LEN * THRESHOLD],
                             uint8_t shares[SHARES_LEN * (SECRET_LEN + 1)])
{
  size_t i, j;

  if (SHARES_LEN > FIELD - 1) return -3;
  if (SHARES_LEN < THRESHOLD) return -2;
  if (THRESHOLD < 2) return -1;

  for (i = 0; i < SECRET_LEN; i++)
  {
    coefficients[i * SECRET_LEN] = secret[i];

    for (j = 0; j < SHARES_LEN; j++)
    {
      /* shares[j * (SECRET_LEN + 1) + i] */
      /* = evaluate(THRESHOLD, coefficients, j + 1); */

      shares[j * (SECRET_LEN + 1) + i]
          = evaluate(THRESHOLD, &coefficients[i * SECRET_LEN], j + 1);

      if (i == SECRET_LEN - 1)
      {
        /* shares[j * (SECRET_LEN + 1) + SECRET_LEN] = j + 1; */
        shares[j * (SECRET_LEN + 1) + SECRET_LEN] = j + 1;
      }
    }
  }

  return 0;
}
