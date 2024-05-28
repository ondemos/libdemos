#include "ring.c"

unsigned int
interpolate(const size_t SHARES_LEN, const uint8_t points[SHARES_LEN][2])
{
  size_t i, j;

  const unsigned int x = 0;

  unsigned int result = 0;

  for (i = 0; i < SHARES_LEN; i++)
  {
    unsigned int weight = 1;

    const unsigned int aX = points[i][0];
    const unsigned int aY = points[i][1];

    for (j = 0; j < SHARES_LEN; j++)
    {
      if (i == j) continue;

      const unsigned int bX = points[j][0];

      weight = multiply(weight, divide(subtract(x, bX), subtract(aX, bX)));
    }

    result = add(result, multiply(aY, weight));
  }

  return result;
};

unsigned int
degree(const size_t THRESHOLD, const uint8_t coefficients[THRESHOLD])
{
  int i = THRESHOLD - 1;

  do
  {
    if (coefficients[i] != 0) return i;
  } while (--i > 0);

  return 0;
};

// Compute y from x
unsigned int
evaluate(const size_t THRESHOLD, const uint8_t coefficients[THRESHOLD],
         const unsigned int x)
{
  if (x == 0) return coefficients[0];

  const unsigned int d = degree(THRESHOLD, coefficients);

  unsigned int y = coefficients[d];

  int i = d - 1;
  do
  {
    y = add(multiply(y, x), coefficients[i]);
  } while (--i >= 0);

  return y;
};
