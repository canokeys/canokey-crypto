// SPDX-License-Identifier: Apache-2.0
#include <algo.h>

const int PRIVATE_KEY_LENGTH[KEY_TYPE_PKC_END] = {32, 32, 48, 32, 32, 32, 128, 192, 256};
const int PUBLIC_KEY_LENGTH[KEY_TYPE_PKC_END] = {64, 64, 96, 64, 32, 32, 256, 384, 512};
const int SIGNATURE_LENGTH[KEY_TYPE_PKC_END] = {64, 64, 96, 64, 64, 64, 256, 384, 512};
