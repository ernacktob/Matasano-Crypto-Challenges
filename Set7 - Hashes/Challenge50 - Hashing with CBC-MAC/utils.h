#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

void cbc_mac(uint8_t mac[AES_BLOCK_SIZE], const uint8_t *in, size_t len, const AES_KEY *key, const uint8_t *iv);
uint8_t *get_padded_string(size_t *padlen, const uint8_t *string, size_t len);
uint8_t *get_unpadded_string(size_t *unpadlen, const uint8_t *padded_string, size_t len);

#endif
