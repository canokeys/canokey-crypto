// SPDX-License-Identifier: Apache-2.0
#ifdef USE_MBEDCRYPTO
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#include <sm2_ke.h>
#include <sm3.h>
#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecp.h>
#include <memzero.h>
#include <rand.h>

#define SM2_KE_SCALAR_SIZE 32

/*
 * KDF of GM/T 0003.2-2012 Section 5.4.3: SM3(x_S || y_S || Z_A || Z_B || ct),
 * ct a big-endian 32-bit counter starting at 1, output truncated to out_len.
 * Z_A must be the initiator's Z and Z_B the responder's Z, on both sides.
 */
static void sm2_ke_kdf(const uint8_t *x, const uint8_t *y, const uint8_t *za, const uint8_t *zb, uint8_t *out,
                       size_t out_len) {
  sm3_ctx_t ctx;
  uint8_t digest[SM3_DIGEST_LENGTH];
  uint32_t ct = 0;
  size_t off = 0;

  while (off < out_len) {
    ++ct;
    const uint8_t ctb[4] = {ct >> 24, ct >> 16, ct >> 8, ct};
    sm3_init(&ctx);
    sm3_update(&ctx, x, SM2_KE_SCALAR_SIZE);
    sm3_update(&ctx, y, SM2_KE_SCALAR_SIZE);
    sm3_update(&ctx, za, SM3_DIGEST_LENGTH);
    sm3_update(&ctx, zb, SM3_DIGEST_LENGTH);
    sm3_update(&ctx, ctb, sizeof(ctb));
    sm3_final(&ctx, digest);
    const size_t take = out_len - off < SM3_DIGEST_LENGTH ? out_len - off : SM3_DIGEST_LENGTH;
    memcpy(out + off, digest, take);
    off += take;
  }
  memzero(digest, sizeof(digest));
}

/*
 * xbar = 2^w + (x & (2^w - 1)) with w = 127 (GM/T 0003.2-2012 Section 6.1),
 * i.e. the low 128 bits of x with the top bit forced to 1.
 */
static int sm2_ke_bar(const uint8_t *x, mbedtls_mpi *bar) {
  uint8_t low[SM2_KE_SCALAR_SIZE / 2];
  memcpy(low, x + SM2_KE_SCALAR_SIZE / 2, sizeof(low));
  low[0] &= 0x7F;
  if (mbedtls_mpi_read_binary(bar, low, sizeof(low)) != 0) return -1;
  if (mbedtls_mpi_set_bit(bar, 127, 1) != 0) return -1;
  return 0;
}

__attribute__((weak)) int sm2_key_exchange(sm2_ke_role_t role, const uint8_t *id_self, const uint8_t *id_peer,
                                           const ecc_key_t *self, const ecc_key_t *eph,
                                           const uint8_t peer_static_pub[64], const uint8_t peer_eph_pub[64],
                                           uint8_t *out, size_t out_len) {
  int ret = -1;
  mbedtls_ecp_group grp = {};
  mbedtls_ecp_point p_static = {};
  mbedtls_ecp_point p_eph = {};
  mbedtls_ecp_point u = {};
  mbedtls_ecp_point s = {};
  mbedtls_mpi xbar = {};
  mbedtls_mpi ybar = {};
  mbedtls_mpi t = {};
  mbedtls_mpi d = {};
  mbedtls_mpi one = {};
  ecc_key_t peer_key;
  uint8_t xs[SM2_KE_SCALAR_SIZE], ys[SM2_KE_SCALAR_SIZE];
  uint8_t z_self[SM3_DIGEST_LENGTH], z_peer[SM3_DIGEST_LENGTH];

  if ((role != SM2_KE_INITIATOR && role != SM2_KE_RESPONDER) || id_self == NULL || id_peer == NULL || self == NULL ||
      eph == NULL || peer_static_pub == NULL || peer_eph_pub == NULL || out == NULL || out_len == 0)
    return -1;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&p_static);
  mbedtls_ecp_point_init(&p_eph);
  mbedtls_ecp_point_init(&u);
  mbedtls_ecp_point_init(&s);
  mbedtls_mpi_init(&xbar);
  mbedtls_mpi_init(&ybar);
  mbedtls_mpi_init(&t);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&one);

  /* SM2 group parameters (same constants as ecc.c, loaded from hex strings) */
  if (mbedtls_mpi_read_string(&grp.P, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF") != 0 ||
      mbedtls_mpi_read_string(&grp.A, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC") != 0 ||
      mbedtls_mpi_read_string(&grp.B, 16, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93") != 0 ||
      mbedtls_mpi_read_string(&grp.G.X, 16, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7") != 0 ||
      mbedtls_mpi_read_string(&grp.G.Y, 16, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0") != 0 ||
      mbedtls_mpi_lset(&grp.G.Z, 1) != 0 ||
      mbedtls_mpi_read_string(&grp.N, 16, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123") != 0)
    goto cleanup;
  grp.pbits = mbedtls_mpi_bitlen(&grp.P);
  grp.nbits = mbedtls_mpi_bitlen(&grp.N);
  // Mbed TLS uses h == 1 for static parameters, not the curve cofactor.
  // These MPIs are heap-owned and must be released by mbedtls_ecp_group_free.
  grp.h = 0;

  /* Both peer points must have field-element coordinates and lie on the SM2 curve. */
  if (mbedtls_mpi_read_binary(&p_static.X, peer_static_pub, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_read_binary(&p_static.Y, peer_static_pub + SM2_KE_SCALAR_SIZE, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_lset(&p_static.Z, 1) != 0 || mbedtls_ecp_check_pubkey(&grp, &p_static) != 0)
    goto cleanup;
  if (mbedtls_mpi_read_binary(&p_eph.X, peer_eph_pub, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_read_binary(&p_eph.Y, peer_eph_pub + SM2_KE_SCALAR_SIZE, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_lset(&p_eph.Z, 1) != 0 || mbedtls_ecp_check_pubkey(&grp, &p_eph) != 0)
    goto cleanup;

  /* t = (self->pri + xbar * eph->pri) mod n */
  if (sm2_ke_bar(eph->pub, &xbar) != 0 || mbedtls_mpi_read_binary(&d, self->pri, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_read_binary(&t, eph->pri, SM2_KE_SCALAR_SIZE) != 0 ||
      mbedtls_mpi_mul_mpi(&t, &t, &xbar) != 0 || mbedtls_mpi_add_mpi(&t, &t, &d) != 0 ||
      mbedtls_mpi_mod_mpi(&t, &t, &grp.N) != 0)
    goto cleanup;
  if (mbedtls_mpi_cmp_int(&t, 0) == 0) goto cleanup;

  /* U = peer_static_pub + [ybar] * peer_eph_pub */
  if (sm2_ke_bar(peer_eph_pub, &ybar) != 0 || mbedtls_mpi_lset(&one, 1) != 0 ||
      mbedtls_ecp_muladd(&grp, &u, &one, &p_static, &ybar, &p_eph) != 0)
    goto cleanup;
  if (mbedtls_ecp_is_zero(&u)) goto cleanup;

  /* S = [t] * U, must not be the point at infinity */
  if (mbedtls_ecp_mul(&grp, &s, &t, &u, mbedtls_rnd, NULL) != 0 || mbedtls_ecp_is_zero(&s)) goto cleanup;
  if (mbedtls_mpi_write_binary(&s.X, xs, sizeof(xs)) != 0 ||
      mbedtls_mpi_write_binary(&s.Y, ys, sizeof(ys)) != 0)
    goto cleanup;

  /* sm2_z only uses the public part of the key */
  memset(&peer_key, 0, sizeof(peer_key));
  memcpy(peer_key.pub, peer_static_pub, 2 * SM2_KE_SCALAR_SIZE);
  if (sm2_z(id_self, self, z_self) != 0 || sm2_z(id_peer, &peer_key, z_peer) != 0) goto cleanup;

  if (role == SM2_KE_INITIATOR) {
    sm2_ke_kdf(xs, ys, z_self, z_peer, out, out_len);
  } else {
    sm2_ke_kdf(xs, ys, z_peer, z_self, out, out_len);
  }
  ret = 0;

cleanup:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&p_static);
  mbedtls_ecp_point_free(&p_eph);
  mbedtls_ecp_point_free(&u);
  mbedtls_ecp_point_free(&s);
  mbedtls_mpi_free(&xbar);
  mbedtls_mpi_free(&ybar);
  mbedtls_mpi_free(&t);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&one);
  memzero(&peer_key, sizeof(peer_key));
  memzero(xs, sizeof(xs));
  memzero(ys, sizeof(ys));
  memzero(z_self, sizeof(z_self));
  memzero(z_peer, sizeof(z_peer));
  return ret;
}
#else
__attribute__((weak)) int sm2_key_exchange(sm2_ke_role_t role, const uint8_t *id_self, const uint8_t *id_peer,
                                           const ecc_key_t *self, const ecc_key_t *eph,
                                           const uint8_t peer_static_pub[64], const uint8_t peer_eph_pub[64],
                                           uint8_t *out, size_t out_len) {
  (void)role;
  (void)id_self;
  (void)id_peer;
  (void)self;
  (void)eph;
  (void)peer_static_pub;
  (void)peer_eph_pub;
  (void)out;
  (void)out_len;
  return -1;
}
#endif
