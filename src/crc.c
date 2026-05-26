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

__attribute__((weak)) uint32_t crc32_update(uint32_t crc, const void *buf, size_t len) {
  static const uint32_t rtable[16] = {
      0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
      0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
  };

  const uint8_t *data = buf;
  for (size_t i = 0; i < len; i++) {
    crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 0)) & 0xf];
    crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 4)) & 0xf];
  }
  return crc;
}
