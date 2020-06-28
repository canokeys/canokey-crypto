// SPDX-License-Identifier: Apache-2.0
#include "ed25519.h"
#include "rand.h"
#include "sha.h"

#ifdef USE_MBEDCRYPTO
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#endif

// reference:
// https://blog.dang.fan/zh-Hans/posts/25519

__attribute__((weak)) void ed25519_publickey(const ed25519_secret_key sk,
                                             ed25519_public_key pk) {
#ifdef USE_MBEDCRYPTO
  // calc sha512 of sk
  uint8_t digest[SHA512_DIGEST_LENGTH];
  sha512_raw(sk, sizeof(ed25519_secret_key), digest);

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
  mbedtls_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED,
                                 &output_len, pk, sizeof(ed25519_public_key));

  // cleanup
  mbedtls_ecp_group_free(&ed25519);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&p);
#else
  (void)sk;
  (void)pk;
#endif
}

__attribute__((weak)) void ed25519_sign(const unsigned char *m, size_t mlen,
                                        const ed25519_secret_key sk,
                                        const ed25519_public_key pk,
                                        ed25519_signature RS) {

#ifdef USE_MBEDCRYPTO
  // calc sha512 of sk
  uint8_t digest[SHA512_DIGEST_LENGTH];
  sha512_raw(sk, sizeof(ed25519_secret_key), digest);
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
  mbedtls_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED,
                                 &output_len, RS, sizeof(ed25519_public_key));

  // k = sha512(R, pk, m)
  uint8_t digest_k[SHA512_DIGEST_LENGTH];
  sha512_init();
  sha512_update(RS, 32);
  sha512_update(pk, sizeof(ed25519_public_key));
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
  mbedtls_mpi_write_binary_le(&k, RS + 32, 32);

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
  (void)RS;
#endif
}