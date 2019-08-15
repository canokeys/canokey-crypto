#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdint.h>

void raise_exception(void);
void print_hex(const uint8_t *buf, size_t len);
CRYPTO_RESULT memcmp_s(const uint8_t *p, const uint8_t *q, size_t len);
void random_delay(void);

#endif //_UTILS_H
