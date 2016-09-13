#ifndef MD4_H
#define MD4_H

#include <stdint.h>

int md4_hash(const uint8_t *message, uint64_t ml, uint8_t hh[16]);
void md4_get_chaining_variables(const uint8_t block[64], uint32_t a[13], uint32_t b[13], uint32_t c[13], uint32_t d[13]);

#endif
