#include "ed25519-hash.h"

void ed25519_hash_init(ed25519_hash_context *ctx) { sha512_init(); }

void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) { sha512_update(in, inlen); }

void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) { sha512_final(hash); }

void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) { sha512_raw(in, inlen, hash); }
