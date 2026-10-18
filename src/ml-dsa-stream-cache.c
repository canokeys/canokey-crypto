// SPDX-License-Identifier: Apache-2.0
#ifdef USE_MBEDCRYPTO
#include "ml-dsa-stream-cache.h"
#include <mbedtls/platform_util.h>

#define MLDSA_STREAM_CACHE_SLOTS 2
static mldsa_stream_cache_t stream_cache[MLDSA_STREAM_CACHE_SLOTS];

mldsa_stream_cache_t *mldsa_stream_cache_acquire(const mldsa_sign_state_t *state) {
  mldsa_stream_cache_t *free_slot = NULL;
  for (size_t i = 0; i < MLDSA_STREAM_CACHE_SLOTS; ++i) {
    if (stream_cache[i].owner == state) return &stream_cache[i];
    if (free_slot == NULL && stream_cache[i].owner == NULL) free_slot = &stream_cache[i];
  }
  return free_slot;
}

mldsa_stream_cache_t *mldsa_stream_cache_find(const mldsa_sign_state_t *state) {
  for (size_t i = 0; i < MLDSA_STREAM_CACHE_SLOTS; ++i) {
    if (stream_cache[i].owner == state) return &stream_cache[i];
  }
  return NULL;
}

void mldsa_stream_cache_release(mldsa_stream_cache_t *slot) {
  if (slot == NULL) return;
  mbedtls_platform_zeroize(slot, sizeof(*slot));
}
#endif
