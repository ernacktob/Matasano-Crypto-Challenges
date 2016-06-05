#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

int sha1_hash(const unsigned char *message, uint64_t ml, uint32_t hh[5]);

#endif
