#include "sha2-generic.h"

static SHA1_CTX sha1;
static SHA256_CTX sha256;
static SHA512_CTX sha512;

__attribute__((weak)) void sha1_init() { sha1_Init(&sha1); }

__attribute__((weak)) void sha1_update(const uint8_t *data, uint16_t len) {
  sha1_Update(&sha1, data, len);
}

__attribute__((weak)) void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_Final(&sha1, digest);
}

void sha1_raw(const uint8_t *data, size_t len,
              uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_init();
  sha1_update(data, len);
  sha1_final(digest);
}

__attribute__((weak)) void sha256_init(void) { sha256_Init(&sha256); }

__attribute__((weak)) void sha256_update(const uint8_t *data, uint16_t len) {
  sha256_Update(&sha256, data, len);
}

__attribute__((weak)) void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_Final(&sha256, digest);
}

void sha256_raw(const uint8_t *data, size_t len,
                uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_init();
  sha256_update(data, len);
  sha256_final(digest);
}

__attribute__((weak)) void sha512_init(void) { sha512_Init(&sha512); }

__attribute__((weak)) void sha512_update(const uint8_t *data, uint16_t len) {
  sha512_Update(&sha512, data, len);
}

__attribute__((weak)) void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_Final(&sha512, digest);
}

void sha512_raw(const uint8_t *data, size_t len,
                uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_init();
  sha512_update(data, len);
  sha512_final(digest);
}
