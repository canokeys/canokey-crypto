/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SM2_KE_H_
#define CANOKEY_CRYPTO_SM2_KE_H_

#include <ecc.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { SM2_KE_INITIATOR = 0, SM2_KE_RESPONDER = 1 } sm2_ke_role_t;

/**
 * SM2 key agreement per GM/T 0003.2-2012 (no key confirmation).
 *
 * All points and scalars are raw big-endian; public keys are X||Y (64 bytes,
 * no 0x04 prefix). Both peer public keys are validated against the SM2 curve
 * before use, and the exchange fails if the shared point is the point at
 * infinity.
 *
 * @param role            SM2_KE_INITIATOR or SM2_KE_RESPONDER
 * @param id_self         Own ID, [len-byte]+ID format (same as sm2_z), e.g. SM2_ID_DEFAULT
 * @param id_peer         Peer ID, same format
 * @param self            Own static key pair (pri + pub filled)
 * @param eph             Own ephemeral key pair (pri + pub filled; use
 *                        ecc_generate/ecc_complete_key with type SM2)
 * @param peer_static_pub Peer's static public key, 64-byte raw X||Y
 * @param peer_eph_pub    Peer's ephemeral public key, 64-byte raw X||Y
 * @param out             KDF output buffer (session key)
 * @param out_len         Requested key length in bytes
 *
 * @return 0 on success, <0 on error (invalid peer point, infinity result, bad params)
 */
int sm2_key_exchange(sm2_ke_role_t role, const uint8_t *id_self, const uint8_t *id_peer, const ecc_key_t *self,
                     const ecc_key_t *eph, const uint8_t peer_static_pub[64], const uint8_t peer_eph_pub[64],
                     uint8_t *out, size_t out_len);

#endif
