#include "aes.h"
#include "aes-generic.h"

__attribute__((weak))
void aes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  WORD aes_key[64];
  aes_key_setup(key, aes_key, 128);
  aes_encrypt(in, out, aes_key, 128);
}

__attribute__((weak))
void aes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  WORD aes_key[64];
  aes_key_setup(key, aes_key, 128);
  aes_decrypt(in, out, aes_key, 128);
}