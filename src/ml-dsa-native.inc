// SPDX-License-Identifier: Apache-2.0
#include MLDSA_HEADER

#include <string.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>

#include "ml-dsa-stream-cache.h"

#undef MLDSA_BETA
#undef MLDSA_K
#undef MLDSA_L
#undef MLDSA_ETA
#undef MLDSA_TAU
#undef MLDSA_GAMMA1
#undef MLDSA_GAMMA2
#undef MLDSA_OMEGA
#undef MLDSA_POLYZ_PACKEDBYTES
#undef MLDSA_POLYW1_PACKEDBYTES
#undef MLDSA_POLYETA_PACKEDBYTES

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize mbedtls_platform_zeroize
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#define MLD_CUSTOM_ALLOC(v, T, N) T *v = mbedtls_calloc((N), sizeof(T))
#define MLD_CUSTOM_FREE(v, T, N) mbedtls_free(v)
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_NAMESPACE_PREFIX MLDSA_NATIVE_PREFIX
#define MLD_CONFIG_PARAMETER_SET MLDSA_PARAMETER_SET
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_NO_SUPERCOP

#include "mldsa_native.h"
/* Keep API declarations before the amalgamated implementation. */
#include "mldsa_native.c"

#define BACKEND_DOMAIN_SEPARATION_MAX_BYTES (2 + 255 + 11 + 64)
#define BACKEND_TR_OFFSET (BACKEND_SEED_BYTES + BACKEND_SEED_BYTES)
#define BACKEND_HINT_BYTES (BACKEND_OMEGA + BACKEND_K)
#define BACKEND_PREHASH_NONE 0

static void mldsa_backend_secure_free(void *buf, size_t len) {
  if (buf == NULL) return;
  mbedtls_platform_zeroize(buf, len);
  mbedtls_free(buf);
}

static int mldsa_backend_validate_msg_ctx(const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len) {
  if (msg == NULL && msg_len != 0) return -1;
  if (ctx == NULL && ctx_len != 0) return -1;
  if (ctx_len > 255) return -1;
  return 0;
}

static int mldsa_backend_build_prefix(uint8_t prefix[BACKEND_DOMAIN_SEPARATION_MAX_BYTES], size_t *prefix_len,
                                      const uint8_t *ctx, size_t ctx_len) {
  if (ctx == NULL && ctx_len != 0) return -1;
  if (ctx_len > 255) return -1;
  *prefix_len = MLDSA_NATIVE(prepare_domain_separation_prefix)(prefix, NULL, 0, ctx, ctx_len, BACKEND_PREHASH_NONE);
  return *prefix_len == 0 ? -1 : 0;
}

static int mldsa_backend_sign_with_sk(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                                      const uint8_t *ctx, size_t ctx_len, const uint8_t *sk) {
  uint8_t prefix[BACKEND_DOMAIN_SEPARATION_MAX_BYTES];
  const uint8_t rnd[BACKEND_SEED_BYTES] = {0};
  size_t prefix_len;

  if (sig == NULL || sig_len == NULL || sk == NULL) return -1;
  if (mldsa_backend_validate_msg_ctx(msg, msg_len, ctx, ctx_len) != 0) return -1;
  if (mldsa_backend_build_prefix(prefix, &prefix_len, ctx, ctx_len) != 0) return -1;

  return MLDSA_NATIVE(signature_internal)(sig, sig_len, msg, msg_len, prefix, prefix_len, rnd, sk, 0);
}

static int mldsa_backend_sign_mu_with_sk(uint8_t *sig, size_t *sig_len, const uint8_t mu[BACKEND_TR_BYTES],
                                         const uint8_t *sk) {
  const uint8_t rnd[BACKEND_SEED_BYTES] = {0};
  if (sig == NULL || sig_len == NULL || mu == NULL || sk == NULL) return -1;
  return MLDSA_NATIVE(signature_internal)(sig, sig_len, mu, BACKEND_TR_BYTES, NULL, 0, rnd, sk, 1);
}

static int mldsa_backend_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
  if (pk == NULL || sk == NULL || seed == NULL) return -1;
  return MLDSA_NATIVE(keypair_internal)(pk, sk, seed);
}

static int mldsa_backend_stream_chunk(const uint8_t *sig, uint8_t phase, const uint8_t **chunk, size_t *chunk_len) {
  if (phase >= 1 && phase <= BACKEND_L) {
    *chunk = sig + BACKEND_C_TILDE_BYTES + (size_t)(phase - 1) * BACKEND_POLYZ_PACKED_BYTES;
    *chunk_len = BACKEND_POLYZ_PACKED_BYTES;
    return 0;
  }

  if (phase == BACKEND_L + 1) {
    *chunk = sig + BACKEND_C_TILDE_BYTES + (size_t)BACKEND_L * BACKEND_POLYZ_PACKED_BYTES;
    *chunk_len = BACKEND_HINT_BYTES;
    return 0;
  }

  return -1;
}
#endif

__attribute__((weak)) int MLDSA_API(sign)(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                                          const uint8_t *ctx, size_t ctx_len, const uint8_t *sk) {
#ifdef USE_MBEDCRYPTO
  return mldsa_backend_sign_with_sk(sig, sig_len, msg, msg_len, ctx, ctx_len, sk);
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

__attribute__((weak)) int MLDSA_API(keygen)(uint8_t *pk, uint8_t *sk, uint8_t *tr, const uint8_t *seed) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf = pk;
  uint8_t *sk_buf = sk;
  int ret;

  if (seed == NULL) return -1;

  if (pk_buf == NULL) {
    pk_buf = mbedtls_calloc(1, BACKEND_PK_BYTES);
    if (pk_buf == NULL) return -1;
  }
  if (sk_buf == NULL) {
    sk_buf = mbedtls_calloc(1, BACKEND_SK_BYTES);
    if (sk_buf == NULL) {
      if (pk == NULL) mbedtls_free(pk_buf);
      return -1;
    }
  }

  ret = mldsa_backend_keypair_from_seed(pk_buf, sk_buf, seed);
  if (ret == 0 && tr != NULL) memcpy(tr, sk_buf + BACKEND_TR_OFFSET, BACKEND_TR_BYTES);

  if (pk == NULL) mbedtls_free(pk_buf);
  if (sk == NULL) mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
  return ret;
#else
  (void)pk;
  (void)sk;
  (void)tr;
  (void)seed;
  return -1;
#endif
}

__attribute__((weak)) int MLDSA_API(seed_to_tr)(uint8_t tr[BACKEND_TR_BYTES], const uint8_t seed[BACKEND_SEED_BYTES]) {
  if (tr == NULL || seed == NULL) return -1;
  return MLDSA_API(keygen)(NULL, NULL, tr, seed);
}

__attribute__((weak)) int MLDSA_API(sign_seed)(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                                               const uint8_t *ctx, size_t ctx_len, const uint8_t *seed,
                                               const uint8_t *tr) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf;
  uint8_t *sk_buf;
  int ret;

  if (seed == NULL || tr == NULL) return -1;
  if (mldsa_backend_validate_msg_ctx(msg, msg_len, ctx, ctx_len) != 0) return -1;

  pk_buf = mbedtls_calloc(1, BACKEND_PK_BYTES);
  sk_buf = mbedtls_calloc(1, BACKEND_SK_BYTES);
  if (pk_buf == NULL || sk_buf == NULL) {
    mbedtls_free(pk_buf);
    mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
    return -1;
  }

  ret = mldsa_backend_keypair_from_seed(pk_buf, sk_buf, seed);
  if (ret == 0) {
    memcpy(sk_buf + BACKEND_TR_OFFSET, tr, BACKEND_TR_BYTES);
    ret = mldsa_backend_sign_with_sk(sig, sig_len, msg, msg_len, ctx, ctx_len, sk_buf);
  }

  mbedtls_free(pk_buf);
  mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
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

static int mldsa_backend_sign_seed_streaming_common(uint8_t *out, size_t out_size, mldsa_sign_state_t *state,
                                                    const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                                                    size_t ctx_len, const uint8_t *tr, const uint8_t *mu,
                                                    uint8_t *hint) {
#ifdef USE_MBEDCRYPTO
  const uint8_t *chunk;
  size_t chunk_len;
  mldsa_stream_cache_t *slot;
  int ret;

  if (out == NULL || state == NULL) return -1;

  if (state->phase == 0) {
    if (out_size < BACKEND_C_TILDE_BYTES || (mu == NULL && tr == NULL)) return -1;

    slot = mldsa_stream_cache_acquire(state);
    if (slot == NULL) return -1;

    if (slot->owner == state) mldsa_stream_cache_release(slot);

    if (mu == NULL) {
      ret = MLDSA_API(sign_seed)(slot->sig, &slot->sig_len, msg, msg_len, ctx, ctx_len, state->seed, tr);
    } else {
      uint8_t *pk_buf = mbedtls_calloc(1, BACKEND_PK_BYTES);
      uint8_t *sk_buf = mbedtls_calloc(1, BACKEND_SK_BYTES);
      if (pk_buf == NULL || sk_buf == NULL) {
        mbedtls_free(pk_buf);
        mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
        mldsa_stream_cache_release(slot);
        return -1;
      }
      ret = mldsa_backend_keypair_from_seed(pk_buf, sk_buf, state->seed);
      if (ret == 0) ret = mldsa_backend_sign_mu_with_sk(slot->sig, &slot->sig_len, mu, sk_buf);
      mbedtls_free(pk_buf);
      mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
    }
    if (ret != 0) {
      mldsa_stream_cache_release(slot);
      return ret;
    }
    if (slot->sig_len != BACKEND_SIG_BYTES) {
      mldsa_stream_cache_release(slot);
      return -1;
    }

    slot->owner = state;
    memcpy(state->c_tilde, slot->sig, BACKEND_C_TILDE_BYTES);
    memcpy(hint, slot->sig + BACKEND_C_TILDE_BYTES + (size_t)BACKEND_L * BACKEND_POLYZ_PACKED_BYTES,
           BACKEND_HINT_BYTES);
    memcpy(out, slot->sig, BACKEND_C_TILDE_BYTES);
    state->phase = 1;
    return BACKEND_C_TILDE_BYTES;
  }

  slot = mldsa_stream_cache_find(state);
  if (slot == NULL || slot->sig_len != BACKEND_SIG_BYTES) {
    state->phase = 0;
    return -1;
  }

  if (mldsa_backend_stream_chunk(slot->sig, state->phase, &chunk, &chunk_len) != 0) {
    mldsa_stream_cache_release(slot);
    state->phase = 0;
    return -1;
  }
  if (out_size < chunk_len) return -1;

  memcpy(out, chunk, chunk_len);
  if (state->phase == BACKEND_L + 1) {
    state->phase = 0;
    mldsa_stream_cache_release(slot);
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
  (void)mu;
  (void)hint;
  return -1;
#endif
}

#if MLDSA_PARAMETER_SET == 65
__attribute__((weak)) int MLDSA_API(sign_seed_streaming)(uint8_t *out, size_t out_size, mldsa_sign_state_t *state,
                                                         const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                                                         size_t ctx_len, const uint8_t *tr) {
  return mldsa_backend_sign_seed_streaming_common(out, out_size, state, msg, msg_len, ctx, ctx_len, tr, NULL,
                                                  state == NULL ? NULL : state->hint);
}

__attribute__((weak)) int MLDSA_API(sign_seed_mu_streaming)(uint8_t *out, size_t out_size, mldsa_sign_state_t *state,
                                                            const uint8_t mu[BACKEND_CRH_BYTES]) {
  if (state != NULL && state->phase == 0 && mu == NULL) return -1;
  return mldsa_backend_sign_seed_streaming_common(out, out_size, state, NULL, 0, NULL, 0, NULL, mu,
                                                  state == NULL ? NULL : state->hint);
}

#else
#include "ml-dsa-44-stream.inc"
#endif

__attribute__((weak)) int MLDSA_API(keygen_streaming)(uint8_t *out, size_t out_size, mldsa_keygen_state_t *state,
                                                      uint8_t *tr_out) {
#ifdef USE_MBEDCRYPTO
  uint8_t *pk_buf;
  uint8_t *sk_buf;
  int ret;

  if (state == NULL) return -1;

  const int tr_only = out == NULL && tr_out != NULL && state->phase == 0;
  if (out == NULL && !tr_only) return -1;

  if (state->phase == 0) {
    if (!tr_only && out_size < BACKEND_SEED_BYTES + 4 * BACKEND_POLYT1_PACKED_BYTES) return -1;
  } else if (state->phase == 1) {
    if (BACKEND_K <= 4 || out_size < (BACKEND_K - 4) * BACKEND_POLYT1_PACKED_BYTES) return -1;
  } else {
    return -1;
  }

  pk_buf = mbedtls_calloc(1, BACKEND_PK_BYTES);
  sk_buf = mbedtls_calloc(1, BACKEND_SK_BYTES);
  if (pk_buf == NULL || sk_buf == NULL) {
    mbedtls_free(pk_buf);
    mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
    return -1;
  }

  ret = mldsa_backend_keypair_from_seed(pk_buf, sk_buf, state->seed);
  if (ret == 0) {
    if (state->phase == 0) {
      if (tr_out != NULL) memcpy(tr_out, sk_buf + BACKEND_TR_OFFSET, BACKEND_TR_BYTES);
      if (tr_only) {
        state->phase = 0;
        ret = 1;
      } else {
        memcpy(out, pk_buf, BACKEND_SEED_BYTES + 4 * BACKEND_POLYT1_PACKED_BYTES);
        state->phase = BACKEND_K > 4 ? 1 : 0;
        ret = BACKEND_SEED_BYTES + 4 * BACKEND_POLYT1_PACKED_BYTES;
      }
    } else {
      memcpy(out, pk_buf + BACKEND_SEED_BYTES + 4 * BACKEND_POLYT1_PACKED_BYTES,
             (BACKEND_K - 4) * BACKEND_POLYT1_PACKED_BYTES);
      state->phase = 0;
      ret = (BACKEND_K - 4) * BACKEND_POLYT1_PACKED_BYTES;
    }
  }

  mbedtls_free(pk_buf);
  mldsa_backend_secure_free(sk_buf, BACKEND_SK_BYTES);
  return ret;
#else
  (void)out;
  (void)out_size;
  (void)state;
  (void)tr_out;
  return -1;
#endif
}

static void mldsa_backend_sign_streaming_abort(mldsa_sign_state_t *state) {
  if (state == NULL) return;
#ifdef USE_MBEDCRYPTO
  mldsa_stream_cache_release(mldsa_stream_cache_find(state));
  mbedtls_platform_zeroize(state, sizeof(*state));
#else
  memset(state, 0, sizeof(*state));
#endif
}

__attribute__((weak)) void MLDSA_API(keygen_streaming_abort)(mldsa_keygen_state_t *state) {
  if (state == NULL) return;
#ifdef USE_MBEDCRYPTO
  mbedtls_platform_zeroize(state, sizeof(*state));
#else
  memset(state, 0, sizeof(*state));
#endif
}

#if MLDSA_PARAMETER_SET == 65
__attribute__((weak)) void ml_dsa_65_sign_streaming_abort(mldsa_sign_state_t *state) {
  mldsa_backend_sign_streaming_abort(state);
}
#endif
