#define __STDC_WANT_LIB_EXT1__ 1  // C11's bounds-checking interface.
#include <string.h>

void memzero(void *const pnt, const size_t len) {
#ifdef __STDC_LIB_EXT1__
  memset_s(pnt, (rsize_t)len, 0, (rsize_t)len);
#else
  volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile) pnt;
  size_t i = (size_t) 0U;

  while (i < len) {
    pnt_[i++] = 0U;
  }
#endif
}
