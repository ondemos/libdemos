#ifndef utils_H
#define utils_H

#include <stdint.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

#define UINT8_NUMBER_LEN 4
#define UINT8_BIGINT_LEN 8

void items_indexes_in_array(
    const size_t ARRAY_LEN, const size_t ITEMS_ARRAY_LEN,
    const uint8_t array[ARRAY_LEN][crypto_hash_sha512_BYTES],
    const uint8_t items[ITEMS_ARRAY_LEN][crypto_hash_sha512_BYTES],
    int32_t indexes[ITEMS_ARRAY_LEN]);

int uint8_array_to_number(const uint8_t array[UINT8_NUMBER_LEN]);

void number_to_uint8_array(const unsigned long number,
                           uint8_t array[UINT8_NUMBER_LEN]);

#endif
