#ifndef _ML_KEM_768_H_
#define _ML_KEM_768_H_

#include <stddef.h>
#include <stdint.h>

/* ML-KEM-768 (FIPS 203) sizes. */
#define MLKEM768_PUBLIC_KEY_BYTES  1184
#define MLKEM768_SECRET_KEY_BYTES  2400
#define MLKEM768_CIPHERTEXT_BYTES  1088
#define MLKEM768_SHARED_KEY_BYTES  32
#define MLKEM768_KEYGEN_SEED_BYTES 64
#define MLKEM768_ENCAPS_SEED_BYTES 32
#define MLKEM768_SECRET_PUBLIC_KEY_OFFSET (MLKEM768_SECRET_KEY_BYTES - MLKEM768_PUBLIC_KEY_BYTES - 2 * MLKEM768_SHARED_KEY_BYTES)

/* Deterministic key generation if seed is non-NULL; randomized otherwise. */
int ml_kem_768_keygen(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]);

/*
 * Deterministic key generation if seed is non-NULL; randomized otherwise.
 * pk may be NULL; dk is still populated with the embedded public key.
 */
int ml_kem_768_keygen_optional_pk(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]);

/*
 * Deterministic key generation if seed is non-NULL; randomized otherwise.
 * ek may be NULL. The decapsulation key is written through write_dk so
 * firmware callers do not need to materialize the 2400-byte key in applet RAM.
 * write_dk must return len on success.
 */
int ml_kem_768_keygen_to_source(uint8_t *ek,
                                int (*write_dk)(void *ctx, size_t offset, const uint8_t *buf, size_t len),
                                void *dk_ctx, const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]);

/* Deterministic encapsulation if coins is non-NULL; randomized otherwise. */
int ml_kem_768_encaps(uint8_t *ct, uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ek,
                      const uint8_t coins[MLKEM768_ENCAPS_SEED_BYTES]);

int ml_kem_768_decaps(uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ct, const uint8_t *dk);

/*
 * Decapsulation with ciphertext loaded from a caller-supplied read callback.
 * Implementations may copy ciphertext into bounded internal scratch before
 * touching crypto/PKE state; callers must not rely on the source after return.
 */
int ml_kem_768_decaps_from_source(uint8_t ss[MLKEM768_SHARED_KEY_BYTES],
                                  int (*read)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *ctx,
                                  const uint8_t *dk);

/*
 * Decapsulation with both ciphertext and decapsulation key loaded from bounded
 * callbacks. This lets platform backends keep large temporaries in their own
 * crypto scratch domain instead of forcing applets to materialize them.
 */
int ml_kem_768_decaps_key_from_source(uint8_t ss[MLKEM768_SHARED_KEY_BYTES],
                                      int (*read_ct)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *ct_ctx,
                                      int (*read_dk)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *dk_ctx);

#endif /* _ML_KEM_768_H_ */
