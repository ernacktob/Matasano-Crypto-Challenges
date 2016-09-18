#ifndef RC4_H
#define RC4_H

#include <stdlib.h>
#include <stdint.h>

#define KEY_LEN		8
#define N 		256

void rc4_init(const uint8_t *key, size_t len);
void rc4_process(uint8_t *result, const uint8_t *data, size_t len);

#endif
