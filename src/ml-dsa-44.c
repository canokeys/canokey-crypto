// SPDX-License-Identifier: Apache-2.0
#define MLDSA_HEADER <ml-dsa-44.h>
#define MLDSA_PARAMETER_SET 44
#define MLDSA_NATIVE_PREFIX canokey_crypto_mldsa44
#define MLDSA_NATIVE(name) canokey_crypto_mldsa44_##name
#define MLDSA_API(name) ml_dsa_44_##name
enum {
  BACKEND_SEED_BYTES = 32,
  BACKEND_CRH_BYTES = 64,
  BACKEND_TR_BYTES = 64,
  BACKEND_C_TILDE_BYTES = 32,
  BACKEND_POLYZ_PACKED_BYTES = 576,
  BACKEND_POLYT1_PACKED_BYTES = 320,
  BACKEND_K = 4,
  BACKEND_L = 4,
  BACKEND_OMEGA = 80,
  BACKEND_PK_BYTES = 1312,
  BACKEND_SK_BYTES = 2560,
  BACKEND_SIG_BYTES = 2420
};
#include "ml-dsa-native.inc"

__attribute__((weak)) void ml_dsa_44_sign_streaming_abort(mldsa44_sign_state_t *state) {
  if (state == NULL) return;
  mldsa_backend_sign_streaming_abort(&state->core);
#ifdef USE_MBEDCRYPTO
  mbedtls_platform_zeroize(state->hint, sizeof(state->hint));
#else
  memset(state->hint, 0, sizeof(state->hint));
#endif
}
