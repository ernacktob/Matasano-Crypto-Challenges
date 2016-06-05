#ifndef MT19937_RAND
#define MT19937_RAND

#include <stdint.h>

void MT19937_srand(uint32_t seed);
uint32_t MT19937_rand();

#endif
