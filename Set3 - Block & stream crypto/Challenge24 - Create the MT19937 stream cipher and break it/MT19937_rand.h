#ifndef MT19937_RAND
#define MT19937_RAND

#include <stdint.h>

#define N			624
#define M			397
#define MATRIX_A		0x9908B0DF
#define UPPER_MASK		0x80000000
#define LOWER_MASK		0x7FFFFFFF

#define TEMPERING_MASK_B	0x9D2C5680
#define TEMPERING_MASK_C	0xEFC60000
#define TEMPERING_SHIFT_U	11
#define TEMPERING_SHIFT_S	7
#define TEMPERING_SHIFT_T	15
#define TEMPERING_SHIFT_L	18

void MT19937_srand(uint32_t seed);
uint32_t MT19937_rand();

#endif
