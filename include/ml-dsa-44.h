// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_ML_DSA_44_H
#define CANOKEY_ML_DSA_44_H

#include <ml-dsa-65.h>

#define MLDSA44_PUBLIC_KEY_BYTES 1312
#define MLDSA44_SECRET_KEY_BYTES 2560
#define MLDSA44_SIGNATURE_BYTES 2420
#define MLDSA44_SEED_BYTES 32
#define MLDSA44_TR_BYTES 64
#define MLDSA44_MU_BYTES 64
#define MLDSA44_POLYZ_BYTES 576
#define MLDSA44_HINT_BYTES 84

/* The existing backend state holds the seed, prefixes and sparse challenge.
 * 44 needs a larger hint encoding; keep it outside the 65 state so existing
 * applet scratch allocations and the 65 public ABI do not grow. Set
 * core.phase=0 and core.seed before the first signing call. Do not switch
 * parameter sets during a stream. */
typedef struct {
  mldsa_sign_state_t core;
  uint8_t hint[MLDSA44_HINT_BYTES];
} mldsa44_sign_state_t;
typedef mldsa_keygen_state_t mldsa44_keygen_state_t;

/* Full-signature host fallback APIs, matching the 65 interface. */
int ml_dsa_44_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                   size_t ctx_len, const uint8_t *sk);
int ml_dsa_44_sign_seed(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                        size_t ctx_len, const uint8_t *seed, const uint8_t *tr);
/* FIPS 204 KeyGen from a 32-byte seed. Each output may be NULL. */
int ml_dsa_44_keygen(uint8_t *pk, uint8_t *sk, uint8_t *tr, const uint8_t *seed);
int ml_dsa_44_seed_to_tr(uint8_t tr[MLDSA44_TR_BYTES], const uint8_t seed[MLDSA44_SEED_BYTES]);
/* Outputs the entire 1312-byte public key in one call, or only tr when
 * out=NULL. Uses the same lifecycle as the 65 streaming interface. */
int ml_dsa_44_keygen_streaming(uint8_t *out, size_t out_size, mldsa44_keygen_state_t *state, uint8_t *tr);
void ml_dsa_44_keygen_streaming_abort(mldsa44_keygen_state_t *state);
/* Signing from seed: first chunk contains c_tilde (32 bytes), optionally
 * followed by z[0]; subsequent chunks contain 576-byte z polynomials and
 * the final 84-byte hint. Return >0 bytes, phase=0 when finished, <0 error.
 * CIU production signing is TRNG-hedged; the native host fallback is
 * deterministic, matching its ML-DSA-65 implementation. */
int ml_dsa_44_sign_seed_streaming(uint8_t *out, size_t out_size, mldsa44_sign_state_t *state, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *tr);
int ml_dsa_44_sign_seed_mu_streaming(uint8_t *out, size_t out_size, mldsa44_sign_state_t *state, const uint8_t *mu);
/* Split-state forms: hint must survive every call and must not overlap out.
 * They allow callers to reserve hints in otherwise unused staging space.
 * Abort split streams with ml_dsa_65_sign_streaming_abort(state), then wipe
 * the caller-owned hint buffer. The common-state abort accepts either set. */
int ml_dsa_44_sign_seed_mu_streaming_split(uint8_t *out, size_t len, mldsa_sign_state_t *state,
                                           uint8_t hint[MLDSA44_HINT_BYTES], const uint8_t *mu);
int ml_dsa_44_sign_seed_streaming_split(uint8_t *out, size_t len, mldsa_sign_state_t *state,
                                        uint8_t hint[MLDSA44_HINT_BYTES], const uint8_t *msg, size_t msg_len,
                                        const uint8_t *ctx, size_t ctx_len, const uint8_t *tr);
void ml_dsa_44_sign_streaming_abort(mldsa44_sign_state_t *state);
#endif
