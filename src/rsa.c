// SPDX-License-Identifier: Apache-2.0
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <rand.h>
#include <rsa.h>
#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/rsa.h>

static int rsa_export_component(const mbedtls_mpi *value, uint8_t *buf, size_t buf_len) {
  memset(buf, 0, buf_len);
  return mbedtls_mpi_write_binary(value, buf, buf_len);
}

static int rsa_init_public_context(mbedtls_rsa_context *rsa, const rsa_key_t *key) {
  const size_t pq_len = key->nbits / 16;

  if (mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(P), key->p, pq_len) < 0 ||
      mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(Q), key->q, pq_len) < 0 ||
      mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(E), key->e, E_LENGTH) < 0 ||
      mbedtls_mpi_mul_mpi(&rsa->MBEDTLS_PRIVATE(N), &rsa->MBEDTLS_PRIVATE(P), &rsa->MBEDTLS_PRIVATE(Q)) < 0) {
    return -1;
  }

  rsa->MBEDTLS_PRIVATE(len) = mbedtls_mpi_size(&rsa->MBEDTLS_PRIVATE(N));
  return mbedtls_rsa_check_pubkey(rsa) < 0 ? -1 : 0;
}

static int rsa_init_private_context(mbedtls_rsa_context *rsa, const rsa_key_t *key) {
  mbedtls_mpi p1, q1, phi;
  int ret = -1;

  mbedtls_mpi_init(&p1);
  mbedtls_mpi_init(&q1);
  mbedtls_mpi_init(&phi);

  // D is a pure function of (P, Q, E) and is needed internally by mbedTLS, so
  // derive it. The CRT parameters DP/DQ/QP, however, must be taken from the
  // key exactly as imported. Silently recomputing them would "repair" corrupt
  // keys instead of rejecting them. mbedtls_rsa_check_privkey validates
  // DP/DQ/QP against (P, Q, D, E) and fails on an inconsistent key.
  if (rsa_init_public_context(rsa, key) < 0 ||
      mbedtls_mpi_sub_int(&p1, &rsa->MBEDTLS_PRIVATE(P), 1) < 0 ||
      mbedtls_mpi_sub_int(&q1, &rsa->MBEDTLS_PRIVATE(Q), 1) < 0 ||
      mbedtls_mpi_mul_mpi(&phi, &p1, &q1) < 0 ||
      mbedtls_mpi_inv_mod(&rsa->MBEDTLS_PRIVATE(D), &rsa->MBEDTLS_PRIVATE(E), &phi) < 0 ||
      mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(DP), key->dp, key->nbits / 16) < 0 ||
      mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(DQ), key->dq, key->nbits / 16) < 0 ||
      mbedtls_mpi_read_binary(&rsa->MBEDTLS_PRIVATE(QP), key->qinv, key->nbits / 16) < 0) {
    goto cleanup;
  }

  if (mbedtls_rsa_check_privkey(rsa) < 0) {
    goto cleanup;
  }

  ret = 0;
cleanup:
  mbedtls_mpi_free(&p1);
  mbedtls_mpi_free(&q1);
  mbedtls_mpi_free(&phi);

  if (ret < 0) {
    return -1;
  }
  return 0;
}
#endif

static int pkcs1_v15_add_padding(const void *in, uint16_t in_len, uint8_t *out, uint16_t out_len) {
  if (out_len < 11 || in_len > out_len - 11) return -1;
  uint16_t pad_size = out_len - in_len - 3;
  memmove(out + pad_size + 3, in, in_len);
  out[0] = 0x00;
  out[1] = 0x01;
  memset(out + 2, 0xFF, pad_size);
  out[2 + pad_size] = 0x00;
  return 0;
}

static int pkcs1_v15_remove_padding(const uint8_t *in, uint16_t in_len, uint8_t *out) {
  if (in_len < 11) return -1;
  if (in[0] != 0x00 || in[1] != 0x02) return -1;
  uint16_t i;
  for (i = 2; i < in_len; ++i)
    if (in[i] == 0x00) break;
  if (i == in_len || i - 2 < 8) return -1;
  memmove(out, in + i + 1, in_len - (i + 1));
  return in_len - (i + 1);
}

__attribute__((weak)) int rsa_generate_key(rsa_key_t *key, uint16_t nbits) {
  int ret = 0;
#ifdef USE_MBEDCRYPTO
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);
  if (mbedtls_rsa_gen_key(&rsa, mbedtls_rnd, NULL, nbits, 65537) < 0) {
    ret = -1;
    goto cleanup;
  }
  const size_t pq_len = nbits / 16;
  if (rsa_export_component(&rsa.MBEDTLS_PRIVATE(P), key->p, pq_len) < 0 ||
      rsa_export_component(&rsa.MBEDTLS_PRIVATE(Q), key->q, pq_len) < 0 ||
      rsa_export_component(&rsa.MBEDTLS_PRIVATE(DP), key->dp, pq_len) < 0 ||
      rsa_export_component(&rsa.MBEDTLS_PRIVATE(DQ), key->dq, pq_len) < 0 ||
      rsa_export_component(&rsa.MBEDTLS_PRIVATE(QP), key->qinv, pq_len) < 0 ||
      rsa_export_component(&rsa.MBEDTLS_PRIVATE(E), key->e, E_LENGTH) < 0) {
    ret = -1;
    goto cleanup;
  }
  key->nbits = nbits;
cleanup:
  mbedtls_rsa_free(&rsa);
#else
  (void)key;
  (void)nbits;
#endif
  return ret;
}

__attribute__((weak)) int rsa_get_public_key(rsa_key_t *key, uint8_t *n) {
  int ret = 0;
#ifdef USE_MBEDCRYPTO
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);
  const size_t n_len = key->nbits / 8;
  if (rsa_init_public_context(&rsa, key) < 0) {
    ret = -1;
    goto cleanup;
  }
  if (rsa_export_component(&rsa.MBEDTLS_PRIVATE(N), n, n_len) < 0) {
    ret = -1;
    goto cleanup;
  }
cleanup:
  mbedtls_rsa_free(&rsa);
#else
  (void)key;
  (void)n;
#endif
  return ret;
}

__attribute__((weak)) int rsa_private(const rsa_key_t *key, const uint8_t *input, uint8_t *output) {
  int ret = 0;
#ifdef USE_MBEDCRYPTO
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);
  if (rsa_init_private_context(&rsa, key) < 0) {
    ret = -1;
    goto cleanup;
  }
  if (mbedtls_rsa_private(&rsa, mbedtls_rnd, NULL, input, output) < 0) {
    ret = -1;
    goto cleanup;
  }
cleanup:
  mbedtls_rsa_free(&rsa);
#else
  (void)key;
  (void)input;
  (void)output;
#endif
  return ret;
}

int rsa_sign_pkcs_v15(const rsa_key_t *key, const uint8_t *data, const size_t len, uint8_t *sig) {
  if (pkcs1_v15_add_padding(data, len, sig, key->nbits / 8) < 0) return -1;
  return rsa_private(key, sig, sig);
}

// Deliberately outside the USE_MBEDCRYPTO guard: this only needs rsa_private,
// which hardware ports override with a strong symbol. In-place input/output is
// required: implementations must read the input fully before writing output,
// as the PIV GA path already relies on in-place rsa_private.
__attribute__((weak)) int rsa_check_crt(const rsa_key_t *key) {
  if (key->nbits == 0 || key->nbits > RSA_N_BIT_MAX || key->nbits % 16 != 0) return -1;
  const size_t pq_len = key->nbits / 16;
  // Structural checks a private-op probe cannot detect: with p == q and
  // self-consistent exponents the CRT congruences still hold, and an even
  // "prime" is never a valid factor.
  if ((key->p[pq_len - 1] & 1) == 0 || (key->q[pq_len - 1] & 1) == 0) return -1;
  if (memcmp(key->p, key->q, pq_len) == 0) return -1;
  // Probe: one private op on a fixed input (well below any valid modulus).
  // rsa_private must verify the CRT result, so inconsistent dp/dq/qinv fail.
  uint8_t probe[RSA_N_BIT_MAX / 8] = {0};
  probe[key->nbits / 8 - 1] = 2;
  return rsa_private(key, probe, probe);
}

int rsa_decrypt_pkcs_v15(const rsa_key_t *key, const uint8_t *in, size_t *olen, uint8_t *out,
                         uint8_t *invalid_padding) {
  *invalid_padding = 0;
  if (rsa_private(key, in, out) < 0) return -1;
  const int len = pkcs1_v15_remove_padding(out, key->nbits / 8, out);
  if (len < 0) {
    *invalid_padding = 1;
    return -1;
  }
  *olen = len;
  return 0;
}
