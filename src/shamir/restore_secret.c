#include <stdlib.h>
#include <string.h>

#include "shamir.h"

int
restore_secret(const unsigned int SHARES_LEN, const unsigned int SECRET_LEN,
               const uint8_t shares[SHARES_LEN][SHARE_LEN(SECRET_LEN)],
               uint8_t secret[SECRET_LEN])
{
  size_t i, j;

  if (SHARES_LEN < 2) return -1;
  if (SHARES_LEN > FIELD - 1) return -2;

  uint8_t(*points)[2] = malloc(sizeof(uint8_t[SHARES_LEN][2]));
  if (points == NULL) return -3;

  for (i = 0; i < SECRET_LEN; i++)
  {
    for (j = 0; j < SHARES_LEN; j++)
    {
      memcpy(&points[j][0], &shares[j][SECRET_LEN], sizeof(uint8_t));
      memcpy(&points[j][1], &shares[j][i], sizeof(uint8_t));
    }

    secret[i] = interpolate(SHARES_LEN, points);
  }

  free(points);

  return 0;
}
