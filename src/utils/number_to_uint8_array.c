#include "utils.h"

void
number_to_uint8_array(const unsigned long number,
                      uint8_t array[UINT8_NUMBER_LEN])
{
  array[0] = (number >> 24) & 0xff; // number & 0xff000000 >> 24;
  array[1] = (number >> 16) & 0xff; // number & 0x00ff0000 >> 16;
  array[2] = (number >> 8) & 0xff;  // number & 0x0000ff00 >> 8;
  array[3] = number & 0xff;         // number & 0x000000ff >> 0;
}
