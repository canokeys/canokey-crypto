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

/* Deterministic key generation if seed is non-NULL; randomized otherwise. */
int ml_kem_768_keygen(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]);

/* Deterministic encapsulation if coins is non-NULL; randomized otherwise. */
int ml_kem_768_encaps(uint8_t *ct, uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ek,
                      const uint8_t coins[MLKEM768_ENCAPS_SEED_BYTES]);

int ml_kem_768_decaps(uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ct, const uint8_t *dk);

#endif /* _ML_KEM_768_H_ */
