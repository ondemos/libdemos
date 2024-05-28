#ifndef split_H
#define split_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FIELD 256
#define SHARE_LEN(SECRET_LEN) SECRET_LEN + 1

unsigned int interpolate(const size_t SHARES_LEN,
                         const uint8_t points[2][SHARES_LEN]);
// const uint8_t points[SHARES_LEN * 2]);

unsigned int evaluate(const size_t threshold,
                      const uint8_t coefficients[threshold],
                      const unsigned int x);

#endif
