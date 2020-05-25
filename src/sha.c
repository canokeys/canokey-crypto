#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <sha.h>
#include <stdint.h>

static mbedtls_sha1_context sha1;
static mbedtls_sha256_context sha256;
static mbedtls_sha512_context sha512;

__attribute__((weak)) void sha1_init() {
  mbedtls_sha1_init(&sha1);
  mbedtls_sha1_starts_ret(&sha1);
}

__attribute__((weak)) void sha1_update(const uint8_t *data, uint16_t len) {
  mbedtls_sha1_update_ret(&sha1, data, len);
}

__attribute__((weak)) void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH]) {
  mbedtls_sha1_finish_ret(&sha1, digest);
  mbedtls_sha1_free(&sha1);
}

void sha1_raw(const uint8_t *data, size_t len,
              uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_init();
  sha1_update(data, len);
  sha1_final(digest);
}

__attribute__((weak)) void sha256_init() {
  mbedtls_sha256_init(&sha256);
  mbedtls_sha256_starts_ret(&sha256, 0);
}

__attribute__((weak)) void sha256_update(const uint8_t *data, uint16_t len) {
  mbedtls_sha256_update_ret(&sha256, data, len);
}

__attribute__((weak)) void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]) {
  mbedtls_sha256_finish_ret(&sha256, digest);
  mbedtls_sha256_free(&sha256);
}

void sha256_raw(const uint8_t *data, size_t len,
                uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_init();
  sha256_update(data, len);
  sha256_final(digest);
}

__attribute__((weak)) void sha512_init() {
  mbedtls_sha512_init(&sha512);
  mbedtls_sha512_starts_ret(&sha512, 0);
}

__attribute__((weak)) void sha512_update(const uint8_t *data, uint16_t len) {
  mbedtls_sha512_update_ret(&sha512, data, len);
}

__attribute__((weak)) void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH]) {
  mbedtls_sha512_finish_ret(&sha512, digest);
  mbedtls_sha512_free(&sha512);
}

void sha512_raw(const uint8_t *data, size_t len,
                uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_init();
  sha512_update(data, len);
  sha512_final(digest);
}
