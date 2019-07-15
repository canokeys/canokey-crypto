#include <stdio.h>
#include "crypto-util.h"

void printHex(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02X", buf[i]);
  printf("\n");
}
