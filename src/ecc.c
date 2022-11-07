// SPDX-License-Identifier: Apache-2.0
#include <ecc.h>
#include <memzero.h>
#include <rand.h>
#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/ecdsa.h>

typedef unsigned char K__ed25519_signature[64];
typedef unsigned char K__ed25519_public_key[32];
typedef unsigned char K__ed25519_secret_key[32];
typedef unsigned char K__x25519_key[32];

static const uint8_t grp_id[] = {
    [SECP256R1] = MBEDTLS_ECP_DP_SECP256R1,
    [SECP256K1] = MBEDTLS_ECP_DP_SECP256K1,
    [SECP384R1] = MBEDTLS_ECP_DP_SECP384R1,
};
#endif

static const K__ed25519_public_key gx = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};

void swap_big_number_endian(uint8_t buf[32]) {
  for (int i = 0; i < 16; ++i) {
    uint8_t tmp = buf[31 - i];
    buf[31 - i] = buf[i];
    buf[i] = tmp;
  }
}

__attribute__((weak)) int ecc_generate(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    if (type == SM2) return -1; // TODO: support SM2

    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_ecp_gen_key(grp_id[type], &keypair, mbedtls_rnd, NULL);
    mbedtls_mpi_write_binary(&keypair.d, key->pri, PRIVATE_KEY_LENGTH[type]);
    mbedtls_mpi_write_binary(&keypair.Q.X, key->pub, PRIVATE_KEY_LENGTH[type]);
    mbedtls_mpi_write_binary(&keypair.Q.Y, key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

    mbedtls_ecp_keypair_free(&keypair);
  } else { // ed25519 & x25519
    random_buffer(key->pri, PRIVATE_KEY_LENGTH[type]);
    if (type == ED25519) {
      K__ed25519_publickey(key->pri, key->pub);
    } else {
      K__x25519_key_from_random(key->pri);
      K__x25519(key->pub, key->pri, gx);
    }
  }
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len,
                                   uint8_t *sig) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    if (type == SM2) return -1; // TODO: support SM2

    mbedtls_mpi r, s, d;
    mbedtls_ecp_group grp;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_group_load(&grp, grp_id[type]);
    mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
    mbedtls_ecdsa_sign(&grp, &r, &s, &d, data_or_digest, PRIVATE_KEY_LENGTH[type], mbedtls_rnd, NULL);
    mbedtls_mpi_write_binary(&r, sig, PRIVATE_KEY_LENGTH[type]);
    mbedtls_mpi_write_binary(&s, sig + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
  } else { // ed25519 & x25519
    if (type == X25519) return -1;
    K__ed25519_signature sig_buf;
    K__ed25519_sign(data_or_digest, len, key->pri, key->pub, sig_buf);
    memcpy(sig, sig_buf, SIGNATURE_LENGTH[ED25519]);
  }
#else
  (void)type;
  (void)key;
  (void)data_or_digest;
  (void)sig;
#endif
  return 0;
}

__attribute__((weak)) int ecc_verify_private_key(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    if (type == SM2) return -1; // TODO: support SM2

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
  } else { // ed25519 & x25519
    return 1;
  }
#else
  (void)type;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int ecc_complete_key(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    if (type == SM2) return -1; // TODO: support SM2

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
  } else { // ed25519 & x25519
    if (type == ED25519) {
      K__ed25519_publickey(key->pri, key->pub);
    } else {
      K__x25519(key->pub, key->pri, gx);
    }
  }
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key,
                               uint8_t *out) {
#ifdef USE_MBEDCRYPTO
  if (!IS_ECC(type)) return -1;

    if (IS_SHORT_WEIERSTRASS(type)) {
      if (type == SM2) return -1; // TODO: support SM2

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
    } else { // ed25519 & x25519
      if (type == ED25519) return -1;
      uint8_t pub[32];
      memcpy(pub, receiver_pub_key, 32);
      swap_big_number_endian(pub);
      K__x25519(out, priv_key, pub);
      swap_big_number_endian(out);
    }
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

__attribute__((weak)) void K__ed25519_publickey(const K__ed25519_secret_key sk, K__ed25519_public_key pk) {
#ifdef USE_MBEDCRYPTO
  // calc sha512 of sk
  uint8_t digest[SHA512_DIGEST_LENGTH];
  sha512_raw(sk, sizeof(K__ed25519_secret_key), digest);

  // normalize
  digest[0] &= 248;
  digest[31] &= 127;
  digest[31] |= 64;

  // init ed25519 group
  mbedtls_ecp_group ed25519;
  mbedtls_ecp_group_init(&ed25519);
  mbedtls_ecp_group_load(&ed25519, MBEDTLS_ECP_DP_ED25519);

  // load digest
  mbedtls_mpi s;
  mbedtls_mpi_init(&s);
  mbedtls_mpi_read_binary_le(&s, digest, 32);

  // P = s*B
  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);
  mbedtls_ecp_mul(&ed25519, &p, &s, &ed25519.G, mbedtls_rnd, NULL);

  // write result
  size_t output_len;
  mbedtls_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED, &output_len, pk,
                                 sizeof(K__ed25519_public_key));

  // cleanup
  mbedtls_ecp_group_free(&ed25519);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&p);
#else
  (void)sk;
  (void)pk;
#endif
}

__attribute__((weak)) void K__ed25519_sign(const unsigned char *m, size_t mlen, const K__ed25519_secret_key sk,
                                           const K__ed25519_public_key pk, K__ed25519_signature rs) {

#ifdef USE_MBEDCRYPTO
  // calc sha512 of sk
  uint8_t digest[SHA512_DIGEST_LENGTH];
  sha512_raw(sk, sizeof(K__ed25519_secret_key), digest);
  // normalize
  digest[0] &= 248;
  digest[31] &= 127;
  digest[31] |= 64;

  // digest[0..32] is s, digest[32..64] is prefix

  // sha512(prefix || m)
  uint8_t digest_m[SHA512_DIGEST_LENGTH];
  sha512_init();
  sha512_update(digest + 32, 32);
  sha512_update(m, mlen);
  sha512_final(digest_m);

  // init ed25519 group
  mbedtls_ecp_group ed25519;
  mbedtls_ecp_group_init(&ed25519);
  mbedtls_ecp_group_load(&ed25519, MBEDTLS_ECP_DP_ED25519);

  // load digest_m into r
  mbedtls_mpi r;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_read_binary_le(&r, digest_m, SHA512_DIGEST_LENGTH);

  // P = r*B
  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);
  mbedtls_ecp_mul(&ed25519, &p, &r, &ed25519.G, mbedtls_rnd, NULL);

  // write result to RS[0..32]
  size_t output_len;
  mbedtls_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED, &output_len, rs,
                                 sizeof(K__ed25519_public_key));

  // k = sha512(R, pk, m)
  uint8_t digest_k[SHA512_DIGEST_LENGTH];
  sha512_init();
  sha512_update(rs, 32);
  sha512_update(pk, sizeof(K__ed25519_public_key));
  sha512_update(m, mlen);
  sha512_final(digest_k);

  mbedtls_mpi k;
  mbedtls_mpi_init(&k);
  mbedtls_mpi_read_binary_le(&k, digest_k, SHA512_DIGEST_LENGTH);
  mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

  // s
  mbedtls_mpi s;
  mbedtls_mpi_init(&s);
  mbedtls_mpi_read_binary_le(&s, digest, 32);
  mbedtls_mpi_mod_mpi(&s, &s, &ed25519.N);

  // k * s
  mbedtls_mpi_mul_mpi(&k, &k, &s);
  mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

  // r + k * s
  mbedtls_mpi_add_mpi(&k, &k, &r);
  mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

  // write result to RS[32..64]
  mbedtls_mpi_write_binary_le(&k, rs + 32, 32);

  // cleanup
  mbedtls_ecp_group_free(&ed25519);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&p);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&s);
#else
  (void)m;
  (void)mlen;
  (void)sk;
  (void)pk;
  (void)rs;
#endif
}

void K__x25519_key_from_random(K__x25519_key private_key) {
  private_key[31] &= 0xf8;
  private_key[0] &= 0x7f;
  private_key[0] |= 0x40;
}

__attribute__((weak)) void K__x25519(K__x25519_key shared_secret, const K__x25519_key private_key,
                                     const K__x25519_key public_key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_ecp_point base;
  mbedtls_ecp_point public;
  mbedtls_ecp_group cv25519;
  mbedtls_mpi sk;

  // init
  mbedtls_ecp_point_init(&base);
  mbedtls_ecp_point_init(&public);
  mbedtls_ecp_group_init(&cv25519);
  mbedtls_mpi_init(&sk);

  // load group
  mbedtls_ecp_group_load(&cv25519, MBEDTLS_ECP_DP_CURVE25519);

  // read base point
  mbedtls_mpi_read_binary(&base.X, public_key, 32);
  mbedtls_mpi_free(&base.Y);
  mbedtls_mpi_lset(&base.Z, 1);

  // read secret
  mbedtls_mpi_read_binary(&sk, private_key, 32);

  // multiply scalar
  mbedtls_ecp_mul(&cv25519, &public, &sk, &base, mbedtls_rnd, NULL);

  // write result
  mbedtls_mpi_write_binary(&public.X, shared_secret, 32);

  mbedtls_ecp_point_free(&base);
  mbedtls_ecp_point_free(&public);
  mbedtls_ecp_group_free(&cv25519);
  mbedtls_mpi_free(&sk);
#else
  (void)shared_secret;
  (void)private_key;
  (void)public_key;
#endif
}
