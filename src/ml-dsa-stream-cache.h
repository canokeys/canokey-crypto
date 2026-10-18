// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_MLDSA_STREAM_CACHE_H
#define CANOKEY_MLDSA_STREAM_CACHE_H
#include <ml-dsa-65.h>

/* Host-only cache shared by both parameter sets. The common-state abort API
 * must also release streams started through the ML-DSA-44 split interface. */
typedef struct {
  const mldsa_sign_state_t *owner;
  uint8_t sig[MLDSA_SIG_BYTES];
  size_t sig_len;
} mldsa_stream_cache_t;

mldsa_stream_cache_t *mldsa_stream_cache_acquire(const mldsa_sign_state_t *state);
mldsa_stream_cache_t *mldsa_stream_cache_find(const mldsa_sign_state_t *state);
void mldsa_stream_cache_release(mldsa_stream_cache_t *slot);
#endif
