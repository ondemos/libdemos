#include "utils.h"

#ifdef __EMSCRIPTEN__

#include <assert.h>
#include <emscripten.h>

uint32_t
randombytes_random(void)
{
  return EM_ASM_INT_V({
    try
    {
      const window_ = 'object' === typeof window ? window : self;
      const crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto
                                                            : window_.msCrypto;
      const buf = new Uint32Array(1);
      crypto_.getRandomValues(buf);

      return buf[0] >>> 0;
    }
    catch (e)
    {
      try
      {
        const crypto = require('crypto');
        const buf = crypto['randomBytes'](4);

        return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
      }
      catch (e)
      {
        throw 'No secure random number generator found';
      }
    }
  });
}

void
randombytes_buf(void *const buf, const size_t size)
{
  if (size > (size_t)0U)
  {
    unsigned char *p = (unsigned char *)buf;
    size_t i;

    for (i = (size_t)0U; i < size; i++)
    {
      p[i] = (unsigned char)randombytes_random();
    }
  }
}

void
randombytes(unsigned char *const buf, const unsigned long long buf_len)
{
  assert(buf_len <= SIZE_MAX);
  randombytes_buf(buf, (size_t)buf_len);
}

#else

#include "../../libsodium/src/libsodium/include/sodium/randombytes.h"

#endif

int
random_bytes(const unsigned int SIZE, uint8_t array[SIZE])
{
  randombytes(array, SIZE);

  return 0;
}
