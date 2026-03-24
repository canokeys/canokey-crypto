# canokey-crypto

[![Tests](https://github.com/canokeys/canokey-crypto/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/canokeys/canokey-crypto/actions/workflows/tests.yml)
[![Coverage](https://coveralls.io/repos/github/canokeys/canokey-crypto/badge.svg?branch=master)](https://coveralls.io/github/canokeys/canokey-crypto?branch=master)

`canokey-crypto` is the cryptography library used by CanoKey firmware.
It provides a small, stable API surface in [`include/`](./include) and ships default software implementations in
[`src/`](./src).

## What is in this library

Public headers:

- `aes.h`, `des.h`, `block-cipher.h`
- `ecc.h`, `rsa.h`, `algo.h`
- `sha.h`, `sm3.h`, `sha3.h`, `hmac.h`
- `rand.h`, `crypto-util.h`, `memzero.h`

Default implementations:

- Symmetric crypto: AES, DES/3DES, block cipher helpers
- Public-key crypto: ECC, RSA
- Hashing: SHA-1, SHA-256, SHA-512, SM3, SHA-3, SHAKE
- Helpers: HMAC, random, byte/format utilities, secure zeroization

## Build

This directory is normally built as part of `canokey-core`, but it can also be built standalone with CMake.

```bash
cmake -S . -B build
cmake --build build
```

Important CMake options:

- `USE_MBEDCRYPTO=ON`
  Use TF-PSA-Crypto / Mbed Crypto as the backend for the default implementations. This is the default.
- `USE_MBEDCRYPTO=OFF`
  Build only the built-in software implementations in `src/`.
- `ENABLE_CRYPTO_TESTS=ON`
  Enable unit tests under [`test/`](./test).
- `TEST_WITH_MBEDCRYPTO=ON`
  When tests are enabled, also build cross-validation tests against Mbed Crypto.

When `USE_MBEDCRYPTO=ON`, the `tf-psa-crypto` submodule must be present.

## API notes

### Hash APIs

`SHA-1`, `SHA-256`, `SHA-512`, and `SM3` use explicit caller-provided context objects:

```c
sha256_ctx_t ctx;
uint8_t digest[SHA256_DIGEST_LENGTH];

sha256_init(&ctx);
sha256_update(&ctx, data, data_len);
sha256_final(&ctx, digest);
```

For one-shot hashing, use the convenience helpers:

- `sha1_raw`
- `sha256_raw`
- `sha512_raw`
- `sm3_raw`
- `sha3_256_raw`
- `sha3_512_raw`
- `shake128_raw`
- `shake256_raw`

### HMAC

HMAC also uses caller-owned context:

```c
HMAC_SHA256_CTX hctx;
uint8_t mac[SHA256_DIGEST_LENGTH];

hmac_sha256_Init(&hctx, key, key_len);
hmac_sha256_Update(&hctx, msg, msg_len);
hmac_sha256_Final(&hctx, mac);
```

One-shot helpers are also available, such as `hmac_sha1`, `hmac_sha256`, and `hmac_sha512`.

### SHA-3 / SHAKE

SHA-3 and SHAKE already use explicit state objects via `SHA3_CTX_T`. The default type is `sha3_ctx_t`; platforms may
override it if they also override the corresponding functions.

## Overriding implementations

Most default implementations in [`src/`](./src) are declared `weak`, so platform firmware can replace selected
functions with hardware-specific or ROM-backed implementations at link time.

In the CanoKey firmware tree, this is how the top-level [`Crypto/`](../../Crypto) directory overrides parts of the
library.

When overriding symbols, make sure the replacement matches the public header exactly. In particular:

- `sha.h` and `sm3.h` now require explicit context parameters.
- `sha3.h` requires the replacement `SHA3_CTX_T` layout to match the replacement implementation.
- Overriding only part of a stateful API is unsafe; override the whole family consistently.

## Tests

To build unit tests:

```bash
cmake -S . -B build -DENABLE_CRYPTO_TESTS=ON
cmake --build build
ctest --test-dir build
```

The test suite uses `cmocka`.

## References

- Mbed TLS / TF-PSA-Crypto: <https://github.com/Mbed-TLS/mbedtls>
- RHash SHA-3 code reference: <https://github.com/rhash/RHash>
