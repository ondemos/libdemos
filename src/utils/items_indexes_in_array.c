#include "./utils.h"

// Output is an array of indexes of the elements
void
items_indexes_in_array(
    const size_t ARRAY_LEN, const size_t ITEMS_ARRAY_LEN,
    const uint8_t array[ARRAY_LEN][crypto_hash_sha512_BYTES],
    const uint8_t items[ITEMS_ARRAY_LEN][crypto_hash_sha512_BYTES],
    int32_t indexes[ITEMS_ARRAY_LEN])
{
  size_t i, j, k;

  for (i = 0; i < ITEMS_ARRAY_LEN; i++)
  {
    // We start with all items unfound
    indexes[i] = -1;
  }

  if (ITEMS_ARRAY_LEN > ARRAY_LEN) return;

  unsigned int itemsFound = 0;
  for (i = 0; i < ARRAY_LEN; i++)
  {
    if (itemsFound == ITEMS_ARRAY_LEN) return;

    for (j = 0; j < ITEMS_ARRAY_LEN; j++)
    {
      bool found = true;
      for (k = 0; k < crypto_hash_sha512_BYTES; k++)
      {
        if (array[i][k] != items[j][k])
        {
          found = false;
          break;
        }
      }

      if (found)
      {
        indexes[j] = i;
        itemsFound++;

        break;
      }
    }
  }
}
