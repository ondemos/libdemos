#include "utils.h"

int
uint8_array_to_number(const uint8_t array[UINT8_NUMBER_LEN])
{
  int n = 0;

  for (int i = 0; i < UINT8_NUMBER_LEN; i++)
  {
    n = (n << 8) | array[i];
  }

  return n;
}
