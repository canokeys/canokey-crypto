#include <rand.h>
#include <stdio.h>

__attribute__((weak)) void raise_exception(void) {}

void print_hex(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02X", buf[i]);
  printf("\n");
}

int memcmp_s(const uint8_t *p, const uint8_t *q, size_t len) {
  size_t equal = 0, notequal = 0;
  for (size_t i = 0; i != len; ++i)
    if (p[i] == q[i])
      ++equal;
    else
      ++notequal;
  if (equal + notequal != len) raise_exception();
  if (equal == len)
    return 0;
  else
    return -1;
}

void random_delay(void) {
  uint16_t delay = random32() & 0xFFFF;
  for (uint16_t i = 0; i != delay; ++i)
    asm volatile("nop");
}
