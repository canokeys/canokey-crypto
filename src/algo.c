// SPDX-License-Identifier: Apache-2.0
#include <algo.h>

const size_t PRIVATE_KEY_LENGTH[KEY_TYPE_PKC_END] = {
    [SECP256R1] = 32, [SECP256K1] = 32, [SECP384R1] = 48,  [SM2] = 32,      [ED25519] = 32, [X25519] = 32,
    [RSA2048] = 128,  [RSA3072] = 192,  [RSA4096] = 256,   [SECP521R1] = 66, [MLKEM768] = 2400,
    [MLDSA65] = 4000,
};
const size_t PUBLIC_KEY_LENGTH[KEY_TYPE_PKC_END] = {
    [SECP256R1] = 64, [SECP256K1] = 64, [SECP384R1] = 96,  [SM2] = 64,       [ED25519] = 32, [X25519] = 32,
    [RSA2048] = 256,  [RSA3072] = 384,  [RSA4096] = 512,   [SECP521R1] = 132, [MLKEM768] = 1184,
    [MLDSA65] = 1952,
};
const size_t SIGNATURE_LENGTH[KEY_TYPE_PKC_END] = {
    [SECP256R1] = 64, [SECP256K1] = 64, [SECP384R1] = 96,  [SM2] = 64,       [ED25519] = 64, [X25519] = 64,
    [RSA2048] = 256,  [RSA3072] = 384,  [RSA4096] = 512,   [SECP521R1] = 132, [MLKEM768] = 0,
    [MLDSA65] = 3309,
};
