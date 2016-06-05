#include <stdio.h>
#include <math.h>
#include <time.h>

#include "MT19937_rand.h"

static uint32_t state[N];
static uint32_t index;

static void twist()
{
	uint32_t y;
	size_t i;

	for (i = 0; i < N; i++) {
		y = (state[i] & UPPER_MASK) | (state[(i + 1) % N] & LOWER_MASK);
		state[i] = state[(i + M) % N] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
	}
}

static uint32_t untemper(uint32_t output)
{
	uint32_t y;

	y = output ^ (output >> TEMPERING_SHIFT_L);
	y ^= (y << TEMPERING_SHIFT_T) & TEMPERING_MASK_C;
	y ^= (y << (2 * TEMPERING_SHIFT_T)) & (TEMPERING_MASK_C << TEMPERING_SHIFT_T) & TEMPERING_MASK_C;
	y ^= (y << TEMPERING_SHIFT_S) & TEMPERING_MASK_B;
	y ^= (y << (2 * TEMPERING_SHIFT_S)) & (TEMPERING_MASK_B << TEMPERING_SHIFT_S) & TEMPERING_MASK_B;
	y ^= (y << (4 * TEMPERING_SHIFT_S)) & (TEMPERING_MASK_B << (3 * TEMPERING_SHIFT_S))
					    & (TEMPERING_MASK_B << (2 * TEMPERING_SHIFT_S))
					    & (TEMPERING_MASK_B << TEMPERING_SHIFT_S)
					    & TEMPERING_MASK_B;
	y ^= (y >> TEMPERING_SHIFT_U);
	y ^= (y >> (2 * TEMPERING_SHIFT_U));
	return y;
}

void clone_rng_state(uint32_t *outputs)
{
	int i;

	for (i = 0; i < N; i++)
		state[i] = untemper(outputs[i]);

	index = 0;
}

uint32_t cloned_rand()
{
	uint32_t y;

	if (index >= N) {
		twist();
		index = 0;
	}

	y = state[index];
	y ^= (y >> TEMPERING_SHIFT_U);
	y ^= ((y << TEMPERING_SHIFT_S) & TEMPERING_MASK_B);
	y ^= ((y << TEMPERING_SHIFT_T) & TEMPERING_MASK_C);
	y ^= (y >> TEMPERING_SHIFT_L);

	index += 1;
	return y;
}

int main()
{
	uint32_t outputs[N];
	uint32_t cloned_outputs[N];
	int i;

	MT19937_srand(time(NULL));

	for (i = 0; i < N; i++)
		outputs[i] = MT19937_rand();

	clone_rng_state(outputs);

	for (i = 0; i < N; i++) {
		if (cloned_rand() != outputs[i]) {
			printf("RNG was not cloned correctly.\n");
			return 0;
		}
	}

	printf("RNG was cloned correctly.\n");
	return 0;
}
