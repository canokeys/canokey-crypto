// SPDX-License-Identifier: Apache-2.0
#include <ecc.h>
#include <memzero.h>
#include <rand.h>
#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/ecdsa.h>

static const uint8_t grp_id[] = {
    [SECP256R1] = MBEDTLS_ECP_DP_SECP256R1,
    [SECP256K1] = MBEDTLS_ECP_DP_SECP256K1,
    [SECP384R1] = MBEDTLS_ECP_DP_SECP384R1,
};
#endif

__attribute__((weak)) int ecc_generate(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_ecp_keypair keypair;
  mbedtls_ecp_keypair_init(&keypair);

  mbedtls_ecp_gen_key(grp_id[type], &keypair, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&keypair.d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.Q.X, key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.Q.Y, key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_ecp_keypair_free(&keypair);
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int ecc_generate_from_seed(key_type_t type, uint8_t *seed, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_ecp_keypair keypair;
  mbedtls_ecp_keypair_init(&keypair);

  mbedtls_ecp_gen_key(grp_id[type], &keypair, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&keypair.d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.Q.X, key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.Q.Y, key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_ecp_keypair_free(&keypair);
#else
  (void)type;
  (void)seed;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *digest, uint8_t *sig) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_mpi r, s, d;
  mbedtls_ecp_group grp;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_ecdsa_sign(&grp, &r, &s, &d, digest, PRIVATE_KEY_LENGTH[type], mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&r, sig, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&s, sig + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
#else
  (void)type;
  (void)key;
  (void)digest;
  (void)sig;
#endif
  return 0;
}

__attribute__((weak)) int ecc_verify(key_type_t type, const ecc_key_t *key, const uint8_t *sig, const uint8_t *digest) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_mpi r, s;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pnt;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pnt);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&pnt.X, key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&pnt.Y, key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_lset(&pnt.Z, 1);
  mbedtls_mpi_read_binary(&r, sig, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&s, sig + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);
  int res = mbedtls_ecdsa_verify(&grp, digest, PRIVATE_KEY_LENGTH[type], &pnt, &r, &s);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pnt);
  return res;
#else
  (void)type;
  (void)key;
  (void)digest;
  (void)sig;
  return 0;
#endif
}

__attribute__((weak)) int ecc_verify_private_key(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  int res = mbedtls_ecp_check_privkey(&grp, &d) == 0 ? 1 : 0;

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return res;
#else
  (void)type;
  (void)priv_key;
  return 0;
#endif
}

__attribute__((weak)) int ecc_complete_key(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pnt;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pnt);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_ecp_mul(&grp, &pnt, &d, &grp.G, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&pnt.X, key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&pnt.Y, key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pnt);
#else
  (void)type;
  (void)priv_key;
  (void)pub_key;
#endif
  return 0;
}

__attribute__((weak)) int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key,
                                       uint8_t *out) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pnt;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pnt);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&d, priv_key, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&pnt.X, receiver_pub_key, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&pnt.Y, receiver_pub_key + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_lset(&pnt.Z, 1);
  mbedtls_ecp_mul(&grp, &pnt, &d, &pnt, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&pnt.X, out, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&pnt.Y, out + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pnt);
#else
  (void)type;
  (void)priv_key;
  (void)receiver_pub_key;
  (void)out;
#endif
  return 0;
}

size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output) {
  int leading_zero_len1 = 0;
  int leading_zero_len2 = 0;
  for (uint8_t i = 0; i < key_len; ++i)
    if (input[i] == 0)
      ++leading_zero_len1;
    else {
      if (input[i] >= 0x80) --leading_zero_len1;
      break;
    }
  for (uint8_t i = key_len; i < key_len * 2; ++i)
    if (input[i] == 0)
      ++leading_zero_len2;
    else {
      if (input[i] >= 0x80) --leading_zero_len2;
      break;
    }
  uint8_t part1_len = key_len - leading_zero_len1;
  uint8_t part2_len = key_len - leading_zero_len2;
  if (leading_zero_len1 < 0) leading_zero_len1 = 0;
  if (leading_zero_len2 < 0) leading_zero_len2 = 0;
  memmove(output + 6 + part1_len + (part2_len == key_len + 1 ? 1 : 0), input + key_len + leading_zero_len2,
          key_len - leading_zero_len2);
  memmove(output + 4 + (part1_len == key_len + 1 ? 1 : 0), input + leading_zero_len1, key_len - leading_zero_len1);
  output[0] = 0x30;
  output[1] = part1_len + part2_len + 4;
  output[2] = 0x02;
  output[3] = part1_len;
  if (part1_len == key_len + 1) output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = part2_len;
  if (part2_len == key_len + 1) output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}
