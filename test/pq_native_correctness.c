// SPDX-License-Identifier: Apache-2.0
#include <ml-dsa-44.h>
#include <ml-kem-512.h>
#include <ml-kem-768.h>
#include <sha.h>
#include <sha3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                                                                    \
  do {                                                                                                                 \
    if (!(expr)) {                                                                                                     \
      fprintf(stderr, "Failed at line %d: %s\n", __LINE__, #expr);                                                     \
      abort();                                                                                                         \
    }                                                                                                                  \
  } while (0)

/* SHA-256 digests generated independently with dilithium-py and kyber-py,
 * seed=00..3f, encapsulation coins=00..1f, message="host PQ regression",
 * context="ctx", deterministic ML-DSA randomness=zero. */
static void check_hash(const uint8_t *data, size_t len, const char *expected) {
  uint8_t digest[32];
  char hex[65];
  sha256_raw(data, len, digest);
  for (size_t i = 0; i < sizeof(digest); ++i)
    sprintf(hex + 2 * i, "%02x", digest[i]);
  CHECK(strcmp(hex, expected) == 0);
}

static void test_dsa(int small) {
  static const uint8_t msg[] = "host PQ regression";
  static const uint8_t ctx[] = "ctx";
  uint8_t seed[32], pk[1952], sk[MLDSA_SK_BYTES], tr[64], derived[64], expected[3309], streamed[3309], out[1312];
  size_t len = 0;
  for (size_t i = 0; i < sizeof(seed); ++i)
    seed[i] = (uint8_t)i;
  int (*keygen)(uint8_t *, uint8_t *, uint8_t *, const uint8_t *) = small ? ml_dsa_44_keygen : ml_dsa_65_keygen;
  CHECK(keygen(pk, sk, tr, seed) == 0);
  check_hash(pk, small ? 1312 : 1952,
             small ? "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"
                   : "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9");
  check_hash(sk, small ? 2560 : MLDSA_SK_BYTES,
             small ? "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b"
                   : "9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063");
  CHECK((small ? ml_dsa_44_seed_to_tr(derived, seed) : ml_dsa_65_seed_to_tr(derived, seed)) == 0);
  CHECK(memcmp(tr, derived, 64) == 0);
  CHECK((small ? ml_dsa_44_sign_seed(expected, &len, msg, sizeof(msg) - 1, ctx, sizeof(ctx) - 1, seed, tr)
               : ml_dsa_65_sign_seed(expected, &len, msg, sizeof(msg) - 1, ctx, sizeof(ctx) - 1, seed, tr)) == 0);
  CHECK(len == (small ? 2420 : 3309));
  check_hash(expected, len,
             small ? "e6c6f284571f801c39acce983b8824979bffe3fa80c06a7dc6bcb62e95ff7a16"
                   : "18626d95ad5262e7d1807bdc7cb70cb0985dec77c50f5b04d41c8692e1cc73cb");

  size_t direct_len = 0;
  CHECK((small ? ml_dsa_44_sign(streamed, &direct_len, msg, sizeof(msg) - 1, ctx, 3, sk)
               : ml_dsa_65_sign(streamed, &direct_len, msg, sizeof(msg) - 1, ctx, 3, sk)) == 0);
  CHECK(direct_len == len && memcmp(streamed, expected, len) == 0);

  mldsa_keygen_state_t key_state = {0};
  memcpy(key_state.seed, seed, 32);
  int n = small ? ml_dsa_44_keygen_streaming(out, sizeof(out), &key_state, derived)
                : ml_dsa_65_keygen_streaming(out, sizeof(out), &key_state, derived);
  CHECK(n == 1312 && memcmp(out, pk, 1312) == 0 && memcmp(derived, tr, 64) == 0);
  CHECK(key_state.phase == (small ? 0 : 1));
  if (!small) {
    CHECK(ml_dsa_65_keygen_streaming(out, sizeof(out), &key_state, NULL) == 640);
    CHECK(memcmp(out, pk + 1312, 640) == 0 && key_state.phase == 0);
  }

  /* Exact chunks, too-small buffer retry, both split and wrapped 44 states,
   * plus precomputed mu (FIPS 204 external-mu signing). */
  uint8_t mu[64];
  sha3_ctx_t hash;
  shake256_init(&hash);
  shake_update(&hash, tr, 64);
  const uint8_t prefix[] = {0, 3, 'c', 't', 'x'};
  shake_update(&hash, prefix, sizeof(prefix));
  shake_update(&hash, msg, sizeof(msg) - 1);
  shake_finalize(&hash);
  shake_squeeze(&hash, mu, 64);
  for (int mode = 0; mode < 3; ++mode) {
    mldsa44_sign_state_t state = {0};
    memcpy(state.core.seed, seed, 32);
    size_t used = 0;
    do {
      if (state.core.phase != 0) {
        uint8_t phase = state.core.phase;
        n = small ? ml_dsa_44_sign_seed_streaming_split(out, 1, &state.core, state.hint, NULL, 0, NULL, 0, NULL)
                  : ml_dsa_65_sign_seed_streaming(out, 1, &state.core, NULL, 0, NULL, 0, NULL);
        CHECK(n < 0 && state.core.phase == phase);
      }
      if (!small) {
        n = mode == 2 ? ml_dsa_65_sign_seed_mu_streaming(out, sizeof(out), &state.core, mu)
                      : ml_dsa_65_sign_seed_streaming(out, sizeof(out), &state.core, msg, sizeof(msg) - 1, ctx, 3, tr);
      } else if (mode == 0) {
        n = ml_dsa_44_sign_seed_streaming(out, sizeof(out), &state, msg, sizeof(msg) - 1, ctx, 3, tr);
      } else if (mode == 1) {
        n = ml_dsa_44_sign_seed_streaming_split(out, sizeof(out), &state.core, state.hint, msg, sizeof(msg) - 1, ctx, 3,
                                                tr);
      } else {
        n = ml_dsa_44_sign_seed_mu_streaming(out, sizeof(out), &state, mu);
      }
      CHECK(n > 0 && used + (size_t)n <= len);
      memcpy(streamed + used, out, (size_t)n);
      used += (size_t)n;
    } while (state.core.phase != 0);
    CHECK(used == len && memcmp(streamed, expected, len) == 0);
  }
  CHECK((small ? ml_dsa_44_sign_seed(expected, &len, msg, sizeof(msg) - 1, NULL, 1, seed, tr)
               : ml_dsa_65_sign_seed(expected, &len, msg, sizeof(msg) - 1, NULL, 1, seed, tr)) < 0);
}

static void test_abort(void) {
  mldsa44_sign_state_t a = {0};
  mldsa_sign_state_t b = {0};
  uint8_t out[640], mu[64] = {0};
  for (int i = 0; i < 5; ++i) {
    CHECK(ml_dsa_44_sign_seed_mu_streaming(out, sizeof(out), &a, mu) > 0);
    CHECK(ml_dsa_65_sign_seed_mu_streaming(out, sizeof(out), &b, mu) > 0);
    /* Applets use the common-state abort API for split 44 streams. */
    ml_dsa_65_sign_streaming_abort(&a.core);
    ml_dsa_65_sign_streaming_abort(&b);
    CHECK(a.core.phase == 0 && b.phase == 0);
  }
  CHECK(ml_dsa_44_sign_seed_mu_streaming(out, sizeof(out), &a, mu) > 0);
  ml_dsa_44_sign_streaming_abort(&a);
  mldsa44_sign_state_t zero = {0};
  CHECK(memcmp(&a, &zero, sizeof(a)) == 0);
}

struct key_source {
  uint8_t bytes[2400];
  int fail;
};
static int write_key(void *ctx, size_t offset, const uint8_t *buf, size_t len) {
  struct key_source *key = ctx;
  CHECK(offset + len <= sizeof(key->bytes));
  if (key->fail) return -1;
  memcpy(key->bytes + offset, buf, len);
  return (int)len;
}
static int read_key(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  struct key_source *key = ctx;
  CHECK(offset + len <= sizeof(key->bytes));
  if (key->fail) return -1;
  memcpy(buf, key->bytes + offset, len);
  return (int)len;
}

static void test_kem(int small) {
  uint8_t seed[64], pk[1184], dk[2400], ct[1088], ss[32], recovered[32], scratch[1184], rejected[32];
  for (size_t i = 0; i < sizeof(seed); ++i)
    seed[i] = (uint8_t)i;
  CHECK((small ? ml_kem_512_keygen(pk, dk, seed) : ml_kem_768_keygen(pk, dk, seed)) == 0);
  check_hash(pk, small ? 800 : 1184,
             small ? "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee"
                   : "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9");
  check_hash(dk, small ? 1632 : 2400,
             small ? "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17"
                   : "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5");
  CHECK((small ? ml_kem_512_seed_to_public(scratch, seed) : ml_kem_768_seed_to_public(scratch, seed)) == 0);
  CHECK(memcmp(pk, scratch, small ? 800 : 1184) == 0);
  CHECK((small ? ml_kem_512_encaps(ct, ss, pk, seed) : ml_kem_768_encaps(ct, ss, pk, seed)) == 0);
  check_hash(ct, small ? 768 : 1088,
             small ? "f3c5b31273a0cab88b74837ebd759b0a995db13bd2c629357ff220bb1d8e31c4"
                   : "39826fe40dc54a3fef68b7c228ed8fb22931012b6fa3bd3e7f204d54db0ac1e1");
  check_hash(ss, sizeof(ss),
             small ? "8c0a68808af5232dc8aaf139a01c23ebed0e3332a165458ba06051afeedefa65"
                   : "0118707cb4fee1ea9004263262448f62d25696336983f298091637c25f1a12dd");
  CHECK((small ? ml_kem_512_decaps_seed(recovered, ct, seed, scratch)
               : ml_kem_768_decaps_seed(recovered, ct, seed, scratch)) == 0);
  CHECK(memcmp(ss, recovered, 32) == 0);
  struct key_source source = {0};
  CHECK((small ? ml_kem_512_keygen_to_source(NULL, write_key, &source, seed)
               : ml_kem_768_keygen_to_source(NULL, write_key, &source, seed)) == 0);
  CHECK(memcmp(source.bytes, dk, small ? 1632 : 2400) == 0);
  CHECK((small ? ml_kem_512_decaps_key_from_source(recovered, ct, read_key, &source)
               : ml_kem_768_decaps_key_from_source(recovered, ct, read_key, &source)) == 0);
  CHECK(memcmp(ss, recovered, 32) == 0);
  source.fail = 1;
  CHECK((small ? ml_kem_512_decaps_key_from_source(recovered, ct, read_key, &source)
               : ml_kem_768_decaps_key_from_source(recovered, ct, read_key, &source)) < 0);
  CHECK((small ? ml_kem_512_keygen_to_source(NULL, write_key, &source, seed)
               : ml_kem_768_keygen_to_source(NULL, write_key, &source, seed)) < 0);
  ct[0] ^= 1;
  sha3_ctx_t hash;
  shake256_init(&hash);
  shake_update(&hash, seed + 32, 32);
  shake_update(&hash, ct, small ? 768 : 1088);
  shake_finalize(&hash);
  shake_squeeze(&hash, rejected, 32);
  CHECK((small ? ml_kem_512_decaps(recovered, ct, dk) : ml_kem_768_decaps(recovered, ct, dk)) == 0);
  CHECK(memcmp(recovered, rejected, 32) == 0);
  CHECK((small ? ml_kem_512_decaps_seed(recovered, ct, seed, scratch)
               : ml_kem_768_decaps_seed(recovered, ct, seed, scratch)) == 0);
  CHECK(memcmp(recovered, rejected, 32) == 0);
}

int main(void) {
  test_dsa(1);
  test_dsa(0);
  test_abort();
  test_kem(1);
  test_kem(0);
  puts("Native PQ KATs, streaming, abort cleanup, callbacks and implicit rejection PASS");
  return 0;
}
