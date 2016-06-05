#ifndef MD4_H
#define MD4_H

#include <stdint.h>

int md4_hash(const uint8_t *message, uint64_t ml, uint32_t hh[4]);
int md4_update(const uint8_t *message, uint64_t ml, const uint32_t prev_hh[4], uint64_t pl, uint32_t hh[4]);

#endif
