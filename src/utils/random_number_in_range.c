#include <math.h>

#include "utils.h"

int
random_number_in_range(const int MIN, const int MAX)
{
  size_t i;

  const unsigned int RANGE = MAX - MIN;
  const unsigned int BYTES_NEEDED = ceil(log2(RANGE) / 8);
  const unsigned int MAX_RANGE = pow(pow(2, 8), BYTES_NEEDED);
  const unsigned int EXTENDED_RANGE = floor(MAX_RANGE / RANGE) * RANGE;

  uint8_t *randomBytes = (uint8_t *)malloc(sizeof(uint8_t[BYTES_NEEDED]));
  if (randomBytes == NULL) return -1;

  int randomInteger = EXTENDED_RANGE;
  while (randomInteger >= EXTENDED_RANGE)
  {
    random_bytes(BYTES_NEEDED, randomBytes);

    randomInteger = 0;
    for (i = 0; i < BYTES_NEEDED; i++)
    {
      randomInteger <<= 8;
      randomInteger += randomBytes[i];
    }

    if (randomInteger < EXTENDED_RANGE)
    {
      free(randomBytes);
      randomInteger %= RANGE;

      return MIN + randomInteger;
    }
  }

  free(randomBytes);

  return randomInteger;
}
