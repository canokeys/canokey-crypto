// SPDX-License-Identifier: Apache-2.0
#ifndef _ML_KEM_512_H_
#define _ML_KEM_512_H_

#include <stddef.h>
#include <stdint.h>

/* ML-KEM-512 (FIPS 203) sizes. */
#define MLKEM512_PUBLIC_KEY_BYTES 800
#define MLKEM512_SECRET_KEY_BYTES 1632
#define MLKEM512_CIPHERTEXT_BYTES 768
#define MLKEM512_SHARED_KEY_BYTES 32
#define MLKEM512_KEYGEN_SEED_BYTES 64
#define MLKEM512_ENCAPS_SEED_BYTES 32
#define MLKEM512_SECRET_PUBLIC_KEY_OFFSET                                                                              \
  (MLKEM512_SECRET_KEY_BYTES - MLKEM512_PUBLIC_KEY_BYTES - 2 * MLKEM512_SHARED_KEY_BYTES)

/* Deterministic key generation if seed is non-NULL; randomized otherwise. */
int ml_kem_512_keygen(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM512_KEYGEN_SEED_BYTES]);

/*
 * Deterministic key generation if seed is non-NULL; randomized otherwise.
 * pk may be NULL; dk is still populated with the embedded public key.
 */
int ml_kem_512_keygen_optional_pk(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM512_KEYGEN_SEED_BYTES]);

/*
 * Deterministic key generation if seed is non-NULL; randomized otherwise.
 * ek may be NULL. The decapsulation key is written through write_dk so
 * firmware callers do not need to materialize the 1632-byte key in applet RAM.
 * write_dk must return len on success.
 */
int ml_kem_512_keygen_to_source(uint8_t *ek, int (*write_dk)(void *ctx, size_t offset, const uint8_t *buf, size_t len),
                                void *dk_ctx, const uint8_t seed[MLKEM512_KEYGEN_SEED_BYTES]);

/* Deterministic encapsulation if coins is non-NULL; randomized otherwise. */
int ml_kem_512_encaps(uint8_t *ct, uint8_t ss[MLKEM512_SHARED_KEY_BYTES], const uint8_t *ek,
                      const uint8_t coins[MLKEM512_ENCAPS_SEED_BYTES]);

int ml_kem_512_decaps(uint8_t ss[MLKEM512_SHARED_KEY_BYTES], const uint8_t *ct, const uint8_t *dk);

/* Derive the encapsulation key without materializing the decapsulation key. */
int ml_kem_512_seed_to_public(uint8_t ek[MLKEM512_PUBLIC_KEY_BYTES], const uint8_t seed[MLKEM512_KEYGEN_SEED_BYTES]);

/*
 * Decapsulate directly from the 64-byte key-generation seed. ek_scratch is
 * caller-owned transient storage and is overwritten with the derived public
 * key; no expanded decapsulation key is materialized.
 */
int ml_kem_512_decaps_seed(uint8_t ss[MLKEM512_SHARED_KEY_BYTES], const uint8_t ct[MLKEM512_CIPHERTEXT_BYTES],
                           const uint8_t seed[MLKEM512_KEYGEN_SEED_BYTES],
                           uint8_t ek_scratch[MLKEM512_PUBLIC_KEY_BYTES]);

/*
 * Decapsulation with an in-memory ciphertext and a decapsulation key loaded
 * from a bounded callback. read_dk must return len on success.
 */
int ml_kem_512_decaps_key_from_source(uint8_t ss[MLKEM512_SHARED_KEY_BYTES],
                                      const uint8_t ct[MLKEM512_CIPHERTEXT_BYTES],
                                      int (*read_dk)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *dk_ctx);

#endif /* _ML_KEM_512_H_ */
