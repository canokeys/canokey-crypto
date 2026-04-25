// SPDX-License-Identifier: Apache-2.0
#include <ml-dsa-65.h>

#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>

enum {
  CANOKEY_MLDSA65_SEED_BYTES = MLDSA_SEEDBYTES,
  CANOKEY_MLDSA65_TR_BYTES = MLDSA_TRBYTES,
  CANOKEY_MLDSA65_C_TILDE_BYTES = MLDSA_C_TILDE_BYTES,
  CANOKEY_MLDSA65_POLYZ_PACKED_BYTES = MLDSA_POLYZ_PACKEDBYTES,
  CANOKEY_MLDSA65_POLYT1_PACKED_BYTES = MLDSA_POLYT1_PACKEDBYTES,
  CANOKEY_MLDSA65_K = MLDSA_K,
  CANOKEY_MLDSA65_L = MLDSA_L,
  CANOKEY_MLDSA65_OMEGA = MLDSA_OMEGA,
  CANOKEY_MLDSA65_PK_BYTES = MLDSA_PK_BYTES,
  CANOKEY_MLDSA65_SK_BYTES = MLDSA_SK_BYTES,
  CANOKEY_MLDSA65_SIG_BYTES = MLDSA_SIG_BYTES
};

#undef MLDSA_BETA

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize mbedtls_platform_zeroize
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#define MLD_CUSTOM_ALLOC(v, T, N) T *v = mbedtls_calloc((N), sizeof(T))
#define MLD_CUSTOM_FREE(v, T, N) mbedtls_free(v)
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_NAMESPACE_PREFIX canokey_crypto_mldsa65
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_NO_SUPERCOP

#include "mldsa_native.h"
#include "mldsa_native.c"

#define MLDSA65_DOMAIN_SEPARATION_MAX_BYTES (2 + 255 + 11 + 64)
#define MLDSA65_TR_OFFSET (CANOKEY_MLDSA65_SEED_BYTES + CANOKEY_MLDSA65_SEED_BYTES)
#define MLDSA65_HINT_BYTES (CANOKEY_MLDSA65_OMEGA + CANOKEY_MLDSA65_K)
#define MLDSA65_PREHASH_NONE 0
#define MLDSA65_STREAM_CACHE_SLOTS 2

typedef struct {
  const mldsa_sign_state_t *owner;
  uint8_t sig[CANOKEY_MLDSA65_SIG_BYTES];
  size_t sig_len;
} mldsa65_stream_cache_t;

static mldsa65_stream_cache_t g_mldsa65_stream_cache[MLDSA65_STREAM_CACHE_SLOTS];

static void mldsa65_secure_free(void *buf, size_t len) {
  if (buf == NULL) return;
  mbedtls_platform_zeroize(buf, len);
  mbedtls_free(buf);
}

static int mldsa65_validate_msg_ctx(const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len) {
  if (msg == NULL && msg_len != 0) return -1;
  if (ctx == NULL && ctx_len != 0) return -1;
  if (ctx_len > 255) return -1;
  return 0;
}

static int mldsa65_build_prefix(uint8_t prefix[MLDSA65_DOMAIN_SEPARATION_MAX_BYTES], size_t *prefix_len, const uint8_t *ctx,
                                size_t ctx_len) {
  if (ctx == NULL && ctx_len != 0) return -1;
  if (ctx_len > 255) return -1;
  *prefix_len =
      canokey_crypto_mldsa65_prepare_domain_separation_prefix(prefix, NULL, 0, ctx, ctx_len, MLDSA65_PREHASH_NONE);
  return *prefix_len == 0 ? -1 : 0;
}

static int mldsa65_sign_with_sk(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                                size_t ctx_len, const uint8_t *sk) {
  uint8_t prefix[MLDSA65_DOMAIN_SEPARATION_MAX_BYTES];
  const uint8_t rnd[CANOKEY_MLDSA65_SEED_BYTES] = {0};
  size_t prefix_len;

  if (sig == NULL || sig_len == NULL || sk == NULL) return -1;
  if (mldsa65_validate_msg_ctx(msg, msg_len, ctx, ctx_len) != 0) return -1;
  if (mldsa65_build_prefix(prefix, &prefix_len, ctx, ctx_len) != 0) return -1;

  return canokey_crypto_mldsa65_signature_internal(sig, sig_len, msg, msg_len, prefix, prefix_len, rnd, sk, 0);
}

static int mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
  if (pk == NULL || sk == NULL || seed == NULL) return -1;
  return canokey_crypto_mldsa65_keypair_internal(pk, sk, seed);
}

static mldsa65_stream_cache_t *mldsa65_stream_cache_acquire(const mldsa_sign_state_t *state) {
  size_t i;
  mldsa65_stream_cache_t *free_slot = NULL;

  for (i = 0; i < MLDSA65_STREAM_CACHE_SLOTS; i++) {
    if (g_mldsa65_stream_cache[i].owner == state) return &g_mldsa65_stream_cache[i];
    if (free_slot == NULL && g_mldsa65_stream_cache[i].owner == NULL) free_slot = &g_mldsa65_stream_cache[i];
  }

  return free_slot;
}

static mldsa65_stream_cache_t *mldsa65_stream_cache_find(const mldsa_sign_state_t *state) {
  size_t i;

  for (i = 0; i < MLDSA65_STREAM_CACHE_SLOTS; i++) {
    if (g_mldsa65_stream_cache[i].owner == state) return &g_mldsa65_stream_cache[i];
  }

  return NULL;
}

static void mldsa65_stream_cache_release(mldsa65_stream_cache_t *slot) {
  if (slot == NULL) return;
  mbedtls_platform_zeroize(slot->sig, sizeof(slot->sig));
  slot->owner = NULL;
  slot->sig_len = 0;
}

static int mldsa65_stream_chunk(const uint8_t *sig, uint8_t phase, const uint8_t **chunk, size_t *chunk_len) {
  if (phase >= 1 && phase <= CANOKEY_MLDSA65_L) {
    *chunk = sig + CANOKEY_MLDSA65_C_TILDE_BYTES + (size_t)(phase - 1) * CANOKEY_MLDSA65_POLYZ_PACKED_BYTES;
    *chunk_len = CANOKEY_MLDSA65_POLYZ_PACKED_BYTES;
    return 0;
  }

  if (phase == CANOKEY_MLDSA65_L + 1) {
    *chunk = sig + CANOKEY_MLDSA65_C_TILDE_BYTES + (size_t)CANOKEY_MLDSA65_L * CANOKEY_MLDSA65_POLYZ_PACKED_BYTES;
    *chunk_len = MLDSA65_HINT_BYTES;
    return 0;
  }

  return -1;
}
#endif

__attribute__((weak)) int ml_dsa_65_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                                         const uint8_t *ctx, size_t ctx_len, const uint8_t *sk) {
#ifdef USE_MBEDCRYPTO
  return mldsa65_sign_with_sk(sig, sig_len, msg, msg_len, ctx, ctx_len, sk);
#else
  (void)sig;
  (void)sig_len;
  (void)msg;
  (void)msg_len;
  (void)ctx;
  (void)ctx_len;
  (void)sk;
  return -1;
#endif
}

__attribute__((weak)) int ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk, uint8_t *tr, const uint8_t *seed) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf = pk;
  uint8_t *sk_buf = sk;
  int ret;

  if (seed == NULL) return -1;

  if (pk_buf == NULL) {
    pk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_PK_BYTES);
    if (pk_buf == NULL) return -1;
  }
  if (sk_buf == NULL) {
    sk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_SK_BYTES);
    if (sk_buf == NULL) {
      if (pk == NULL) mbedtls_free(pk_buf);
      return -1;
    }
  }

  ret = mldsa65_keypair_from_seed(pk_buf, sk_buf, seed);
  if (ret == 0 && tr != NULL) memcpy(tr, sk_buf + MLDSA65_TR_OFFSET, CANOKEY_MLDSA65_TR_BYTES);

  if (pk == NULL) mbedtls_free(pk_buf);
  if (sk == NULL) mldsa65_secure_free(sk_buf, CANOKEY_MLDSA65_SK_BYTES);
  return ret;
#else
  (void)pk;
  (void)sk;
  (void)tr;
  (void)seed;
  return -1;
#endif
}

__attribute__((weak)) int ml_dsa_65_sign_seed(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                                              const uint8_t *ctx, size_t ctx_len, const uint8_t *seed,
                                              const uint8_t *tr) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf;
  uint8_t *sk_buf;
  int ret;

  if (seed == NULL || tr == NULL) return -1;
  if (mldsa65_validate_msg_ctx(msg, msg_len, ctx, ctx_len) != 0) return -1;

  pk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_PK_BYTES);
  sk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_SK_BYTES);
  if (pk_buf == NULL || sk_buf == NULL) {
    mbedtls_free(pk_buf);
    mldsa65_secure_free(sk_buf, CANOKEY_MLDSA65_SK_BYTES);
    return -1;
  }

  ret = mldsa65_keypair_from_seed(pk_buf, sk_buf, seed);
  if (ret == 0) {
    memcpy(sk_buf + MLDSA65_TR_OFFSET, tr, CANOKEY_MLDSA65_TR_BYTES);
    ret = mldsa65_sign_with_sk(sig, sig_len, msg, msg_len, ctx, ctx_len, sk_buf);
  }

  mbedtls_free(pk_buf);
  mldsa65_secure_free(sk_buf, CANOKEY_MLDSA65_SK_BYTES);
  return ret;
#else
  (void)sig;
  (void)sig_len;
  (void)msg;
  (void)msg_len;
  (void)ctx;
  (void)ctx_len;
  (void)seed;
  (void)tr;
  return -1;
#endif
}

__attribute__((weak)) int ml_dsa_65_sign_seed_streaming(uint8_t *out, size_t out_size, mldsa_sign_state_t *state,
                                                        const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                                                        size_t ctx_len, const uint8_t *tr) {
#ifdef USE_MBEDCRYPTO
  const uint8_t *chunk;
  size_t chunk_len;
  mldsa65_stream_cache_t *slot;
  int ret;

  if (out == NULL || state == NULL) return -1;

  if (state->phase == 0) {
    if (out_size < CANOKEY_MLDSA65_C_TILDE_BYTES || tr == NULL) return -1;

    slot = mldsa65_stream_cache_acquire(state);
    if (slot == NULL) return -1;

    if (slot->owner == state) mldsa65_stream_cache_release(slot);

    ret = ml_dsa_65_sign_seed(slot->sig, &slot->sig_len, msg, msg_len, ctx, ctx_len, state->seed, tr);
    if (ret != 0) {
      mldsa65_stream_cache_release(slot);
      return ret;
    }
    if (slot->sig_len != CANOKEY_MLDSA65_SIG_BYTES) {
      mldsa65_stream_cache_release(slot);
      return -1;
    }

    slot->owner = state;
    memcpy(state->c_tilde, slot->sig, CANOKEY_MLDSA65_C_TILDE_BYTES);
    memcpy(state->hint,
           slot->sig + CANOKEY_MLDSA65_C_TILDE_BYTES +
               (size_t)CANOKEY_MLDSA65_L * CANOKEY_MLDSA65_POLYZ_PACKED_BYTES,
           MLDSA65_HINT_BYTES);
    memcpy(out, slot->sig, CANOKEY_MLDSA65_C_TILDE_BYTES);
    state->phase = 1;
    return CANOKEY_MLDSA65_C_TILDE_BYTES;
  }

  slot = mldsa65_stream_cache_find(state);
  if (slot == NULL || slot->sig_len != CANOKEY_MLDSA65_SIG_BYTES) {
    state->phase = 0;
    return -1;
  }

  if (mldsa65_stream_chunk(slot->sig, state->phase, &chunk, &chunk_len) != 0) {
    mldsa65_stream_cache_release(slot);
    state->phase = 0;
    return -1;
  }
  if (out_size < chunk_len) return -1;

  memcpy(out, chunk, chunk_len);
  if (state->phase == CANOKEY_MLDSA65_L + 1) {
    state->phase = 0;
    mldsa65_stream_cache_release(slot);
  } else {
    state->phase++;
  }
  return (int)chunk_len;
#else
  (void)out;
  (void)out_size;
  (void)state;
  (void)msg;
  (void)msg_len;
  (void)ctx;
  (void)ctx_len;
  (void)tr;
  return -1;
#endif
}

__attribute__((weak)) int ml_dsa_65_keygen_streaming(uint8_t *out, size_t out_size, mldsa_keygen_state_t *state,
                                                     uint8_t *tr_out) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf;
  uint8_t *sk_buf;
  int ret;

  if (out == NULL || state == NULL) return -1;

  if (state->phase == 0) {
    if (out_size < CANOKEY_MLDSA65_SEED_BYTES + 4 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES) return -1;
  } else if (state->phase == 1) {
    if (out_size < 2 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES) return -1;
  } else {
    return -1;
  }

  pk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_PK_BYTES);
  sk_buf = mbedtls_calloc(1, CANOKEY_MLDSA65_SK_BYTES);
  if (pk_buf == NULL || sk_buf == NULL) {
    mbedtls_free(pk_buf);
    mldsa65_secure_free(sk_buf, CANOKEY_MLDSA65_SK_BYTES);
    return -1;
  }

  ret = mldsa65_keypair_from_seed(pk_buf, sk_buf, state->seed);
  if (ret == 0) {
    if (state->phase == 0) {
      memcpy(out, pk_buf, CANOKEY_MLDSA65_SEED_BYTES + 4 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES);
      if (tr_out != NULL) memcpy(tr_out, sk_buf + MLDSA65_TR_OFFSET, CANOKEY_MLDSA65_TR_BYTES);
      state->phase = 1;
      ret = CANOKEY_MLDSA65_SEED_BYTES + 4 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES;
    } else {
      memcpy(out, pk_buf + CANOKEY_MLDSA65_SEED_BYTES + 4 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES,
             2 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES);
      state->phase = 0;
      ret = 2 * CANOKEY_MLDSA65_POLYT1_PACKED_BYTES;
    }
  }

  mbedtls_free(pk_buf);
  mldsa65_secure_free(sk_buf, CANOKEY_MLDSA65_SK_BYTES);
  return ret;
#else
  (void)out;
  (void)out_size;
  (void)state;
  (void)tr_out;
  return -1;
#endif
}
