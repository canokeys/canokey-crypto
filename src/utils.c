#include <stdio.h>
#include "utils.h"

void printHex(const uint8_t *buf, const size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02X", buf[i]);
  printf("\n");
}
