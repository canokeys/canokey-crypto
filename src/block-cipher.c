#include <block-cipher.h>
#include <string.h>

static void xor_buf(const uint8_t *in, uint8_t *out, size_t len);
static void increment_iv(uint8_t *iv, uint8_t block_size);

int block_cipher_enc(block_cipher_config *cfg) {
  if (cfg->block_size % 8 != 0 || cfg->in_size % cfg->block_size != 0)
    return -1;

  uint8_t buf_in[cfg->block_size], iv_buf[cfg->block_size];
  int blocks = cfg->in_size / cfg->block_size;

  if (cfg->mode != ECB) {
    if (cfg->iv == NULL)
      return -1;
    memcpy(iv_buf, cfg->iv, cfg->block_size);
  }

  for (int idx = 0; idx < blocks; idx++) {
    switch (cfg->mode) {
    case ECB:
      cfg->encrypt(cfg->in + idx * cfg->block_size,
                   cfg->out + idx * cfg->block_size, cfg->key);
      break;
    case CBC:
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      cfg->encrypt(buf_in, cfg->out + idx * cfg->block_size, cfg->key);
      cfg->encrypt(buf_in, iv_buf, cfg->key);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      break;
    case CFB:
      cfg->encrypt(iv_buf, iv_buf, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      break;
    case OFB:
      cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      break;
    case CTR:
      cfg->encrypt(iv_buf, buf_in, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      increment_iv(iv_buf, cfg->block_size);
      break;
    }
  }

  return 0;
}

int block_cipher_dec(block_cipher_config *cfg) {
  if (cfg->block_size % 8 != 0 || cfg->in_size % cfg->block_size != 0)
    return -1;

  uint8_t buf_in[cfg->block_size], iv_buf[cfg->block_size];
  int blocks = cfg->in_size / cfg->block_size;

  if (cfg->mode != ECB) {
    if (cfg->iv == NULL)
      return -1;
    memcpy(iv_buf, cfg->iv, cfg->block_size);
  }

  for (int idx = 0; idx < blocks; idx++) {
    switch (cfg->mode) {
    case ECB:
      cfg->decrypt(cfg->in + idx * cfg->block_size,
                   cfg->out + idx * cfg->block_size, cfg->key);
      break;
    case CBC:
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      cfg->decrypt(buf_in, cfg->out + idx * cfg->block_size, cfg->key);
      xor_buf(iv_buf, cfg->out + idx * cfg->block_size, cfg->block_size);
      memcpy(iv_buf, buf_in, cfg->block_size);
      break;
    case CFB:
      cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(cfg->in + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(iv_buf, buf_in, cfg->block_size);
      break;
    case OFB:
      cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      break;
    case CTR:
      cfg->encrypt(iv_buf, buf_in, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      increment_iv(iv_buf, cfg->block_size);
      break;
    }
  }

  return 0;
}

static void xor_buf(const uint8_t *in, uint8_t *out, size_t len) {
  size_t idx;

  for (idx = 0; idx < len; idx++)
    out[idx] ^= in[idx];
}

static void increment_iv(uint8_t *iv, uint8_t block_size) {
  for (int idx = block_size - 1; idx >= 0; idx--) {
    iv[idx]++;
    if (iv[idx] != 0)
      break;
  }
}
