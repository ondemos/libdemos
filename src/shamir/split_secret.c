#include <stdlib.h>

#include "../utils/utils.h"
#include "shamir.h"

int
split_secret(const unsigned int SHARES_LEN, const unsigned int THRESHOLD,
             const unsigned int SECRET_LEN, const uint8_t secret[SECRET_LEN],
             uint8_t shares[SHARES_LEN][SHARE_LEN(SECRET_LEN)])
{
  size_t i, j;

  if (SHARES_LEN > FIELD - 1) return -3;
  if (SHARES_LEN < THRESHOLD) return -2;
  if (THRESHOLD < 2) return -1;

  uint8_t *coefficients = malloc(sizeof(uint8_t[THRESHOLD]));
  if (coefficients == NULL) return -4;

  for (i = 0; i < SECRET_LEN; i++)
  {
    random_bytes(THRESHOLD, coefficients);
    coefficients[0] = secret[i];

    for (j = 0; j < SHARES_LEN; j++)
    {
      /* shares[j * (SECRET_LEN + 1) + i] */
      /* = evaluate(THRESHOLD, coefficients, j + 1); */

      shares[j][i] = evaluate(THRESHOLD, coefficients, j + 1);

      if (i == SECRET_LEN - 1)
      {
        /* shares[j * (SECRET_LEN + 1) + SECRET_LEN] = j + 1; */
        shares[j][SECRET_LEN] = j + 1;
      }
    }
  }

  free(coefficients);

  return 0;
}
