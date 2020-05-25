/*
        Public domain by Andrew M. <liquidsun@gmail.com>

        Ed25519 reference implementation using Ed25519-donna
*/

#include "ed25519.h"
#include "ed25519-donna.h"
#include "ed25519-hash.h"

/*
  Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/
static void ed25519_extsk(hash_512bits extsk, const ed25519_secret_key sk) {
  ed25519_hash(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;
}

static void ed25519_hram(hash_512bits hram, const ed25519_signature RS, const ed25519_public_key pk,
                         const unsigned char *m, size_t mlen) {
  ed25519_hash_context ctx;
  ed25519_hash_init(&ctx);
  ed25519_hash_update(&ctx, RS, 32);
  ed25519_hash_update(&ctx, pk, 32);
  ed25519_hash_update(&ctx, m, mlen);
  ed25519_hash_final(&ctx, hram);
}

/*
__attribute__((weak)) void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk) {
  bignum256modm a;
  ge25519 ALIGN(16) A;
  hash_512bits extsk;

  ed25519_extsk(extsk, sk);
  printf("sha512: ");
  for (int i = 0; i < 64;i++)
    printf("%02X", extsk[i]);
  printf("\n");

  expand256_modm(a, extsk, 32);
  printf("k: ");
  for (int i = 0; i < 9;i++)
    printf("%08X", a[i]);
  printf("\n");
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
  ge25519_pack(pk, &A);
  printf("pk: ");
  for (int i = 0; i < 32;i++)
    printf("%02X", pk[i]);
  printf("\n");
}
*/

__attribute__((weak)) void ed25519_sign_old(const unsigned char *m, size_t mlen, const ed25519_secret_key sk,
                                        const ed25519_public_key pk, ed25519_signature RS) {
  ed25519_hash_context ctx;
  bignum256modm r, S, a;
  ge25519 ALIGN(16) R;
  hash_512bits extsk, hashr, hram;

  ed25519_extsk(extsk, sk);

  /* r = H(aExt[32..64], m) */
  ed25519_hash_init(&ctx);
  ed25519_hash_update(&ctx, extsk + 32, 32);
  ed25519_hash_update(&ctx, m, mlen);
  ed25519_hash_final(&ctx, hashr);
  expand256_modm(r, hashr, 64);

  /* R = rB */
  ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
  ge25519_pack(RS, &R);

  /* S = H(R,A,m).. */
  ed25519_hram(hram, RS, pk, m, mlen);
  expand256_modm(S, hram, 64);

  /* S = H(R,A,m)a */
  expand256_modm(a, extsk, 32);
  mul256_modm(S, S, a);

  /* S = (r + H(R,A,m)a) */
  add256_modm(S, S, r);

  /* S = (r + H(R,A,m)a) mod L */
  contract256_modm(RS + 32, S);
}

#include "curve25519-donna-scalarmult-base.h"

/*
__attribute__((weak)) void curve25519_scalarmult(curve25519_key mypublic, const curve25519_key secret,
                                                 const curve25519_key basepoint) {
  curve25519_key e;
  size_t i;

  for (i = 0; i < 32; ++i)
    e[i] = secret[i];
  e[0] &= 0xf8;
  e[31] &= 0x7f;
  e[31] |= 0x40;
  curve25519_scalarmult_donna(mypublic, e, basepoint);
}
*/
