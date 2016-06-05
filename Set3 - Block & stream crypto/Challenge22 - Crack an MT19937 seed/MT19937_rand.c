#include <stdlib.h>
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

static uint32_t mt_state[N];
static size_t index;

static void twist()
{
	uint32_t y;
	size_t i;

	for (i = 0; i < N; i++) {
		y = (mt_state[i] & UPPER_MASK) | (mt_state[(i + 1) % N] & LOWER_MASK);
		mt_state[i] = mt_state[(i + M) % N] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
	}
}

void MT19937_srand(uint32_t seed)
{
	uint32_t i;

	mt_state[0] = seed;

	for (i = 1; i < N; i++)
		mt_state[i] = 1812433253 * (mt_state[i - 1] ^ (mt_state[i - 1] >> 30)) + i;

	index = N;
}

uint32_t MT19937_rand()
{
	uint32_t y;

	if (index >= N) {
		twist();
		index = 0;
	}

	y = mt_state[index];
	y ^= (y >> TEMPERING_SHIFT_U);
	y ^= ((y << TEMPERING_SHIFT_S) & TEMPERING_MASK_B);
	y ^= ((y << TEMPERING_SHIFT_T) & TEMPERING_MASK_C);
	y ^= (y >> TEMPERING_SHIFT_L);

	index += 1;
	return y;
}
