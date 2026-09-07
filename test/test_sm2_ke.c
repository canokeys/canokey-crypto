// SPDX-License-Identifier: Apache-2.0
#ifdef USE_MBEDCRYPTO
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#include "ecc.h"
#include "sm2_ke.h"

#ifdef USE_MBEDCRYPTO
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecp.h>
#include <rand.h>
#endif

/*
 * Official example of GM/T 0003.5-2012 Annex A (SM2 key exchange, klen = 128 bits).
 * IDs are the ASCII string "1234567812345678" for both parties, i.e. SM2_ID_DEFAULT.
 * Values cross-checked against:
 *   - https://github.com/meshplus/crypto-gm/blob/master/sm2_test.go ("sm2DHAGMT1" case,
 *     also carries the x_S/y_S/Z_A/Z_B intermediates)
 *   - https://github.com/Tencent/TencentKonaSMSuite/blob/master/kona-crypto/src/test/java/
 *     com/tencent/kona/crypto/provider/SM2KeyAgreementTest.java
 */

static const uint8_t vec_da[32] = "\x81\xEB\x26\xE9\x41\xBB\x5A\xF1\x6D\xF1\x16\x49\x5F\x90\x69\x52"
                                  "\x72\xAE\x2C\xD6\x3D\x6C\x4A\xE1\x67\x84\x18\xBE\x48\x23\x00\x29";
static const uint8_t vec_pa[64] = "\x16\x0E\x12\x89\x7D\xF4\xED\xB6\x1D\xD8\x12\xFE\xB9\x67\x48\xFB"
                                  "\xD3\xCC\xF4\xFF\xE2\x6A\xA6\xF6\xDB\x95\x40\xAF\x49\xC9\x42\x32"
                                  "\x4A\x7D\xAD\x08\xBB\x9A\x45\x95\x31\x69\x4B\xEB\x20\xAA\x48\x9D"
                                  "\x66\x49\x97\x5E\x1B\xFC\xF8\xC4\x74\x1B\x78\xB4\xB2\x23\x00\x7F";
static const uint8_t vec_ra[32] = "\xD4\xDE\x15\x47\x4D\xB7\x4D\x06\x49\x1C\x44\x0D\x30\x5E\x01\x24"
                                  "\x00\x99\x0F\x3E\x39\x0C\x7E\x87\x15\x3C\x12\xDB\x2E\xA6\x0B\xB3";
static const uint8_t vec_eph_a[64] = "\x64\xCE\xD1\xBD\xBC\x99\xD5\x90\x04\x9B\x43\x4D\x0F\xD7\x34\x28"
                                     "\xCF\x60\x8A\x5D\xB8\xFE\x5C\xE0\x7F\x15\x02\x69\x40\xBA\xE4\x0E"
                                     "\x37\x66\x29\xC7\xAB\x21\xE7\xDB\x26\x09\x22\x49\x9D\xDB\x11\x8F"
                                     "\x07\xCE\x8E\xAA\xE3\xE7\x72\x0A\xFE\xF6\xA5\xCC\x06\x20\x70\xC0";
static const uint8_t vec_db[32] = "\x78\x51\x29\x91\x7D\x45\xA9\xEA\x54\x37\xA5\x93\x56\xB8\x23\x38"
                                  "\xEA\xAD\xDA\x6C\xEB\x19\x90\x88\xF1\x4A\xE1\x0D\xEF\xA2\x29\xB5";
static const uint8_t vec_pb[64] = "\x6A\xE8\x48\xC5\x7C\x53\xC7\xB1\xB5\xFA\x99\xEB\x22\x86\xAF\x07"
                                  "\x8B\xA6\x4C\x64\x59\x1B\x8B\x56\x6F\x73\x57\xD5\x76\xF1\x6D\xFB"
                                  "\xEE\x48\x9D\x77\x16\x21\xA2\x7B\x36\xC5\xC7\x99\x20\x62\xE9\xCD"
                                  "\x09\xA9\x26\x43\x86\xF3\xFB\xEA\x54\xDF\xF6\x93\x05\x62\x1C\x4D";
static const uint8_t vec_rb[32] = "\x7E\x07\x12\x48\x14\xB3\x09\x48\x91\x25\xEA\xED\x10\x11\x13\x16"
                                  "\x4E\xBF\x0F\x34\x58\xC5\xBD\x88\x33\x5C\x1F\x9D\x59\x62\x43\xD6";
static const uint8_t vec_eph_b[64] = "\xAC\xC2\x76\x88\xA6\xF7\xB7\x06\x09\x8B\xC9\x1F\xF3\xAD\x1B\xFF"
                                     "\x7D\xC2\x80\x2C\xDB\x14\xCC\xCC\xDB\x0A\x90\x47\x1F\x9B\xD7\x07"
                                     "\x2F\xED\xAC\x04\x94\xB2\xFF\xC4\xD6\x85\x38\x76\xC7\x9B\x8F\x30"
                                     "\x1C\x65\x73\xAD\x0A\xA5\x0F\x39\xFC\x87\x18\x1E\x1A\x1B\x46\xFE";
static const uint8_t vec_za[32] = "\x3B\x85\xA5\x71\x79\xE1\x1E\x7E\x51\x3A\xA6\x22\x99\x1F\x2C\xA7"
                                  "\x4D\x18\x07\xA0\xBD\x4D\x4B\x38\xF9\x09\x87\xA1\x7A\xC2\x45\xB1";
static const uint8_t vec_zb[32] = "\x79\xC9\x88\xD6\x32\x29\xD9\x7E\xF1\x9F\xE0\x2C\xA1\x05\x6E\x01"
                                  "\xE6\xA7\x41\x1E\xD2\x46\x94\xAA\x8F\x83\x4F\x4A\x4A\xB0\x22\xF7";
static const uint8_t vec_key16[16] = "\x6C\x89\x34\x73\x54\xDE\x24\x84\xC6\x0B\x4A\xB1\xFD\xE4\xC6\xE5";

static void make_key(ecc_key_t *key, const uint8_t *pri, const uint8_t *pub) {
  memset(key, 0, sizeof(*key));
  memcpy(key->pri, pri, 32);
  memcpy(key->pub, pub, 64);
}

static void test_sm2_ke_gmt_vector(void **state) {
  (void)state;
  ecc_key_t a, b, eph_a, eph_b;
  make_key(&a, vec_da, vec_pa);
  make_key(&b, vec_db, vec_pb);
  make_key(&eph_a, vec_ra, vec_eph_a);
  make_key(&eph_b, vec_rb, vec_eph_b);

  // The example public keys must match the private keys
  ecc_key_t derived;
  memset(&derived, 0, sizeof(derived));
  memcpy(derived.pri, vec_da, 32);
  assert_int_equal(ecc_complete_key(SM2, &derived), 0);
  assert_memory_equal(derived.pub, vec_pa, 64);
  memcpy(derived.pri, vec_db, 32);
  assert_int_equal(ecc_complete_key(SM2, &derived), 0);
  assert_memory_equal(derived.pub, vec_pb, 64);
  memcpy(derived.pri, vec_ra, 32);
  assert_int_equal(ecc_complete_key(SM2, &derived), 0);
  assert_memory_equal(derived.pub, vec_eph_a, 64);
  memcpy(derived.pri, vec_rb, 32);
  assert_int_equal(ecc_complete_key(SM2, &derived), 0);
  assert_memory_equal(derived.pub, vec_eph_b, 64);

  // Intermediate Z values of the example
  uint8_t z[32];
  assert_int_equal(sm2_z(SM2_ID_DEFAULT, &a, z), 0);
  assert_memory_equal(z, vec_za, 32);
  assert_int_equal(sm2_z(SM2_ID_DEFAULT, &b, z), 0);
  assert_memory_equal(z, vec_zb, 32);

  // Initiator A and responder B must agree on the example session key
  uint8_t ka16[16], kb16[16];
  assert_int_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb, vec_eph_b,
                                    ka16, sizeof(ka16)),
                   0);
  assert_memory_equal(ka16, vec_key16, sizeof(ka16));
  assert_int_equal(sm2_key_exchange(SM2_KE_RESPONDER, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &b, &eph_b, vec_pa, vec_eph_a,
                                    kb16, sizeof(kb16)),
                   0);
  assert_memory_equal(kb16, vec_key16, sizeof(kb16));

  // A longer output is a KDF stream extension: same prefix, both sides agree
  uint8_t ka32[32], kb32[32];
  assert_int_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb, vec_eph_b,
                                    ka32, sizeof(ka32)),
                   0);
  assert_int_equal(sm2_key_exchange(SM2_KE_RESPONDER, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &b, &eph_b, vec_pa, vec_eph_a,
                                    kb32, sizeof(kb32)),
                   0);
  assert_memory_equal(ka32, kb32, sizeof(ka32));
  assert_memory_equal(ka32, vec_key16, sizeof(vec_key16));
}

static void test_sm2_ke_random_roundtrip(void **state) {
  (void)state;
  ecc_key_t a, b, eph_a, eph_b;
  assert_int_equal(ecc_generate(SM2, &a), 0);
  assert_int_equal(ecc_generate(SM2, &b), 0);
  assert_int_equal(ecc_generate(SM2, &eph_a), 0);
  assert_int_equal(ecc_generate(SM2, &eph_b), 0);

  uint8_t ka[48], kb[48];
  assert_int_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, b.pub, eph_b.pub, ka,
                                    sizeof(ka)),
                   0);
  assert_int_equal(sm2_key_exchange(SM2_KE_RESPONDER, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &b, &eph_b, a.pub, eph_a.pub, kb,
                                    sizeof(kb)),
                   0);
  assert_memory_equal(ka, kb, sizeof(ka));

  // Distinct IDs break the agreement (Z values differ per side ordering)
  const uint8_t id_other[] = {0x05, 'A', 'l', 'i', 'c', 'e'};
  assert_int_equal(sm2_key_exchange(SM2_KE_RESPONDER, id_other, SM2_ID_DEFAULT, &b, &eph_b, a.pub, eph_a.pub, kb,
                                    sizeof(kb)),
                   0);
  assert_memory_not_equal(ka, kb, sizeof(ka));
}

static void test_sm2_ke_reject_invalid_peer_point(void **state) {
  (void)state;
  ecc_key_t a, eph_a;
  make_key(&a, vec_da, vec_pa);
  make_key(&eph_a, vec_ra, vec_eph_a);
  uint8_t out[16];
  uint8_t bad_pub[64];

  // Peer static point off the curve (flip one bit of Y)
  memcpy(bad_pub, vec_pb, sizeof(bad_pub));
  bad_pub[63] ^= 0x01;
  assert_int_not_equal(
      sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, bad_pub, vec_eph_b, out,
                       sizeof(out)),
      0);

  // Peer static point coordinates out of the base field (X == p)
  memcpy(bad_pub, vec_pb, sizeof(bad_pub));
  memcpy(bad_pub,
         "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
         "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
         32);
  assert_int_not_equal(
      sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, bad_pub, vec_eph_b, out,
                       sizeof(out)),
      0);

  // Peer ephemeral point off the curve (all zeros is not on the curve)
  memset(bad_pub, 0, sizeof(bad_pub));
  assert_int_not_equal(
      sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb, bad_pub, out,
                       sizeof(out)),
      0);

  // Bad parameters
  assert_int_not_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb,
                                        vec_eph_b, out, 0),
                       0);
  assert_int_not_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb,
                                        vec_eph_b, NULL, sizeof(out)),
                       0);
  assert_int_not_equal(sm2_key_exchange((sm2_ke_role_t)2, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, vec_pb,
                                        vec_eph_b, out, sizeof(out)),
                       0);
}

/*
 * Force S to the point at infinity: pick R_B = [r]G and set the peer static
 * point to P_B = -[ybar]R_B, so U = P_B + [ybar]R_B = O. Both peer points are
 * valid curve points, so the exchange must fail on the infinity check.
 */
static void test_sm2_ke_reject_infinity(void **state) {
  (void)state;
#ifdef USE_MBEDCRYPTO
  int ret = -1;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point r_b, p_b;
  mbedtls_mpi r, ybar, neg;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&r_b);
  mbedtls_ecp_point_init(&p_b);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&ybar);
  mbedtls_mpi_init(&neg);

  mbedtls_mpi_read_string(&grp.P, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
  mbedtls_mpi_read_string(&grp.A, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
  mbedtls_mpi_read_string(&grp.B, 16, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
  mbedtls_mpi_read_string(&grp.G.X, 16, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
  mbedtls_mpi_read_string(&grp.G.Y, 16, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
  mbedtls_mpi_lset(&grp.G.Z, 1);
  mbedtls_mpi_read_string(&grp.N, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
  grp.pbits = mbedtls_mpi_bitlen(&grp.P);
  grp.nbits = mbedtls_mpi_bitlen(&grp.N);
  grp.h = 1;

  uint8_t r_buf[32];
  memset(r_buf, 0, sizeof(r_buf));
  r_buf[31] = 0x2A;
  if (mbedtls_mpi_read_binary(&r, r_buf, sizeof(r_buf)) != 0) goto cleanup;
  if (mbedtls_ecp_mul(&grp, &r_b, &r, &grp.G, mbedtls_rnd, NULL) != 0) goto cleanup;

  // ybar = 2^127 + (R_B.x & (2^127 - 1))
  uint8_t x32[32], xb[16];
  if (mbedtls_mpi_write_binary(&r_b.X, x32, sizeof(x32)) != 0) goto cleanup;
  memcpy(xb, x32 + 16, 16);
  xb[0] &= 0x7F;
  if (mbedtls_mpi_read_binary(&ybar, xb, sizeof(xb)) != 0) goto cleanup;
  if (mbedtls_mpi_set_bit(&ybar, 127, 1) != 0) goto cleanup;

  // neg = n - ybar, then P_B = [neg]R_B = -[ybar]R_B
  if (mbedtls_mpi_sub_mpi(&neg, &grp.N, &ybar) != 0) goto cleanup;
  if (mbedtls_ecp_mul(&grp, &p_b, &neg, &r_b, mbedtls_rnd, NULL) != 0) goto cleanup;

  uint8_t peer_static[64], peer_eph[64];
  if (mbedtls_mpi_write_binary(&p_b.X, peer_static, 32) != 0 ||
      mbedtls_mpi_write_binary(&p_b.Y, peer_static + 32, 32) != 0 ||
      mbedtls_mpi_write_binary(&r_b.X, peer_eph, 32) != 0 ||
      mbedtls_mpi_write_binary(&r_b.Y, peer_eph + 32, 32) != 0)
    goto cleanup;
  if (mbedtls_ecp_check_pubkey(&grp, &p_b) != 0) goto cleanup; // sanity: it is a valid point

  ecc_key_t a, eph_a;
  make_key(&a, vec_da, vec_pa);
  make_key(&eph_a, vec_ra, vec_eph_a);
  uint8_t out[16];
  assert_int_not_equal(sm2_key_exchange(SM2_KE_INITIATOR, SM2_ID_DEFAULT, SM2_ID_DEFAULT, &a, &eph_a, peer_static,
                                        peer_eph, out, sizeof(out)),
                       0);
  ret = 0;

cleanup:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&r_b);
  mbedtls_ecp_point_free(&p_b);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&ybar);
  mbedtls_mpi_free(&neg);
  assert_int_equal(ret, 0);
#else
  cmocka_skip();
#endif
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_sm2_ke_gmt_vector),
      cmocka_unit_test(test_sm2_ke_random_roundtrip),
      cmocka_unit_test(test_sm2_ke_reject_invalid_peer_point),
      cmocka_unit_test(test_sm2_ke_reject_infinity),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
