/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_CRC_H
#define CANOKEY_CRYPTO_CRC_H

#include <stddef.h>
#include <stdint.h>

#define CRC16_IBM_SDLC_INIT 0xffff
#define CRC16_IBM_SDLC_RESIDUE 0xf0b8

uint16_t crc16_ibm_sdlc_raw(const uint8_t *buf, size_t len);
uint16_t crc16_ibm_sdlc(const uint8_t *buf, size_t len);

#endif // CANOKEY_CRYPTO_CRC_H
