#ifndef _ML_DSA_65_H_
#define _ML_DSA_65_H_

#include <stddef.h>
#include <stdint.h>

/* ML-DSA-65 (FIPS 204) parameters */
#define MLDSA_Q          8380417
#define MLDSA_N          256
#define MLDSA_D          13
#define MLDSA_TAU        49
#define MLDSA_LAMBDA     192
#define MLDSA_GAMMA1     (1 << 19)
#define MLDSA_GAMMA2     ((MLDSA_Q - 1) / 32)  /* 261888 */
#define MLDSA_K          6
#define MLDSA_L          5
#define MLDSA_ETA        4
#define MLDSA_BETA       (MLDSA_TAU * MLDSA_ETA) /* 196 */
#define MLDSA_OMEGA      55

/* Derived sizes (bytes) */
#define MLDSA_SEEDBYTES       32
#define MLDSA_CRHBYTES        64
#define MLDSA_TRBYTES         64
#define MLDSA_C_TILDE_BYTES   48   /* lambda / 4 */
#define MLDSA_POLYW1_PACKEDBYTES  128  /* 256 * 4 / 8 */

/* Secret key component packed sizes */
#define MLDSA_POLYETA_PACKEDBYTES   128  /* eta=4: 4 bits per coeff, 256*4/8 */
#define MLDSA_POLYT0_PACKEDBYTES    416  /* 13 bits per coeff, 256*13/8 */
#define MLDSA_POLYZ_PACKEDBYTES     640  /* gamma1=2^19: 20 bits, 256*20/8 */
#define MLDSA_POLYT1_PACKEDBYTES    320  /* 10 bits per coeff, 256*10/8 */

/* Key sizes */
#define MLDSA_PK_BYTES  (MLDSA_SEEDBYTES + MLDSA_K * MLDSA_POLYT1_PACKEDBYTES)
/* 32 + 6*320 = 1952 bytes */

#define MLDSA_SK_BYTES (MLDSA_SEEDBYTES + MLDSA_SEEDBYTES + MLDSA_TRBYTES \
                        + MLDSA_L * MLDSA_POLYETA_PACKEDBYTES             \
                        + MLDSA_K * MLDSA_POLYETA_PACKEDBYTES             \
                        + MLDSA_K * MLDSA_POLYT0_PACKEDBYTES)
/* 32 + 32 + 64 + 5*128 + 6*128 + 6*416 = 4000 bytes */

/* Signature size */
#define MLDSA_SIG_BYTES (MLDSA_C_TILDE_BYTES                   \
                         + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES    \
                         + MLDSA_OMEGA + MLDSA_K)
/* 48 + 5*640 + 55 + 6 = 3309 bytes */

/**
 * ML-DSA-65 signing (FIPS 204, Algorithm 7 – ML-DSA.Sign).
 *
 * @param sig     Output signature buffer, MLDSA_SIG_BYTES bytes.
 * @param sig_len Set to the actual signature length on success.
 * @param msg     Message to sign.
 * @param msg_len Length of message.
 * @param ctx     Context string (may be NULL if ctx_len == 0).
 * @param ctx_len Context string length (0..255).
 * @param sk      Secret key, MLDSA_SK_BYTES bytes.
 *
 * @return 0 on success, negative on failure.
 */
int ml_dsa_65_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len,
                   const uint8_t *sk);

/**
 * ML-DSA-65 key generation (FIPS 204, Algorithm 6 – ML-DSA.KeyGen).
 *
 * Any of pk, sk, tr may be NULL — the corresponding output is skipped.
 * tr = H(pk) is computed via streaming, no pk buffer needed.
 *
 * @param pk      Output public key buffer (MLDSA_PK_BYTES), or NULL.
 * @param sk      Output secret key buffer (MLDSA_SK_BYTES), or NULL.
 * @param tr      Output tr hash (MLDSA_TRBYTES), or NULL.
 * @param seed    32-byte random seed (xi).
 *
 * @return 0 on success, negative on failure.
 */
int ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk, uint8_t *tr,
                     const uint8_t *seed);

/**
 * ML-DSA-65 signing from seed (no sk buffer needed).
 *
 * Regenerates s1, s2, t0 from seed on the fly.
 * Approximately 2x slower than ml_dsa_65_sign due to recomputation.
 *
 * @param sig     Output signature buffer, MLDSA_SIG_BYTES bytes.
 * @param sig_len Set to the actual signature length on success.
 * @param msg     Message to sign.
 * @param msg_len Length of message.
 * @param ctx     Context string (may be NULL if ctx_len == 0).
 * @param ctx_len Context string length (0..255).
 * @param seed    32-byte seed used in keygen.
 * @param tr      Pre-computed tr (MLDSA_TRBYTES), from keygen.
 *
 * @return 0 on success, negative on failure.
 */
int ml_dsa_65_sign_seed(uint8_t *sig, size_t *sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *ctx, size_t ctx_len,
                        const uint8_t *seed, const uint8_t *tr);

/* ---- Streaming output variants ---- */

/* State for streaming sign_seed.  Caller allocates (static or stack).
 * Set phase=0 before first call; subsequent calls use phase>0.
 * After the final chunk (when state->phase becomes 0), the state may be discarded. */
typedef struct {
  uint8_t phase;               /* 0=first call/done, 1..L=z[0..L-1], L+1=hint */
  uint8_t seed[32];
  uint8_t rho_prime_sign[64];
  uint8_t rho_prime_keygen[64];
  uint8_t c_tilde[MLDSA_C_TILDE_BYTES]; /* 48 */
  uint8_t hint[MLDSA_OMEGA + MLDSA_K];  /* 61 */
  uint8_t challenge_pos[MLDSA_TAU];
  int8_t challenge_sign[MLDSA_TAU];
  uint16_t kappa;
} mldsa_sign_state_t;

/* Streaming sign from seed+tr.
 *
 * phase 0 (first call):
 *   Runs the full signing algorithm (passes 1-3).
 *   Outputs c_tilde (48 bytes) to out.
 *   Saves intermediate state for subsequent calls.
 *   msg, ctx, tr must be valid.
 *
 * phase 1..L (subsequent calls):
 *   Recomputes z[j] from state and outputs one full packed z polynomial
 *   (MLDSA_POLYZ_PACKEDBYTES = 640 bytes) per call.
 *
 * phase L+1 (final call):
 *   Outputs hint (MLDSA_OMEGA + MLDSA_K bytes).
 *
 * phase > 0 calls:
 *   msg, ctx, tr are ignored (may be NULL).
 *
 * Returns:
 *   >0  bytes written to out; if state->phase > 0, more chunks remain.
 *       if state->phase == 0 after return, this was the final chunk.
 *   <0  error
 */
int ml_dsa_65_sign_seed_streaming(
    uint8_t *out, size_t out_size,
    mldsa_sign_state_t *state,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *tr);

/* State for streaming keygen (pk export). */
typedef struct {
  uint8_t phase;
  uint8_t seed[32];
} mldsa_keygen_state_t;

/* Streaming keygen (pk export from seed).
 *
 * phase 0: outputs rho(32) + t1[0..3](1280) = 1312 bytes.
 *          If tr_out != NULL, computes tr = H(pk) by hashing all 6 rows
 *          (t1[4..5] computed for hashing only, recomputed in phase 1).
 *          tr_out is only written in phase 0.
 * phase 1: outputs t1[4..5](640) = 640 bytes.
 *
 * Returns: >0 bytes written; state->phase==0 means done. <0 error.
 */
int ml_dsa_65_keygen_streaming(
    uint8_t *out, size_t out_size,
    mldsa_keygen_state_t *state,
    uint8_t *tr_out);

#endif /* _ML_DSA_65_H_ */
