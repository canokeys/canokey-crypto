// SPDX-License-Identifier: Apache-2.0
__attribute__((weak)) int ml_dsa_44_sign_seed_streaming_split(uint8_t *out, size_t len, mldsa_sign_state_t *state,
                                                              uint8_t hint[MLDSA44_HINT_BYTES], const uint8_t *msg,
                                                              size_t msg_len, const uint8_t *ctx, size_t ctx_len,
                                                              const uint8_t *tr) {
  if (hint == NULL) return -1;
  return mldsa_backend_sign_seed_streaming_common(out, len, state, msg, msg_len, ctx, ctx_len, tr, NULL, hint);
}

__attribute__((weak)) int ml_dsa_44_sign_seed_mu_streaming_split(uint8_t *out, size_t len, mldsa_sign_state_t *state,
                                                                 uint8_t hint[MLDSA44_HINT_BYTES], const uint8_t *mu) {
  if (hint == NULL || (state != NULL && state->phase == 0 && mu == NULL)) return -1;
  return mldsa_backend_sign_seed_streaming_common(out, len, state, NULL, 0, NULL, 0, NULL, mu, hint);
}

__attribute__((weak)) int ml_dsa_44_sign_seed_streaming(uint8_t *out, size_t len, mldsa44_sign_state_t *state,
                                                        const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                                                        size_t ctx_len, const uint8_t *tr) {
  if (state == NULL) return -1;
  return ml_dsa_44_sign_seed_streaming_split(out, len, &state->core, state->hint, msg, msg_len, ctx, ctx_len, tr);
}

__attribute__((weak)) int ml_dsa_44_sign_seed_mu_streaming(uint8_t *out, size_t len, mldsa44_sign_state_t *state,
                                                           const uint8_t *mu) {
  if (state == NULL) return -1;
  return ml_dsa_44_sign_seed_mu_streaming_split(out, len, &state->core, state->hint, mu);
}
