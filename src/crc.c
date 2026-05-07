// SPDX-License-Identifier: Apache-2.0
#include <crc.h>

__attribute__((weak)) uint16_t crc16_ibm_sdlc_raw(const uint8_t *buf, size_t len) {
  uint16_t crc = CRC16_IBM_SDLC_INIT;

  while (len--) {
    crc ^= *buf++;
    for (uint8_t i = 0; i < 8; i++) {
      const uint8_t carry = crc & 1;
      crc >>= 1;
      if (carry) crc ^= 0x8408;
    }
  }

  return crc;
}

__attribute__((weak)) uint16_t crc16_ibm_sdlc(const uint8_t *buf, size_t len) {
  return (uint16_t)~crc16_ibm_sdlc_raw(buf, len);
}
