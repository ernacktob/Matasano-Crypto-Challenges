#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "MT19937_rand.h"

static uint32_t real_seed;

uint32_t get_rng_output()
{
	unsigned int seconds;

	seconds = rand() % 960 + 40;
	sleep(seconds);

	real_seed = time(NULL);
	MT19937_srand(real_seed);

	seconds = rand() % 960 + 40;
	sleep(seconds);

	return MT19937_rand();
}

uint32_t crack_rng_seed(uint32_t output)
{
	uint32_t seed;
	uint32_t start;

	start = time(NULL);
	seed = start;

	do {
		MT19937_srand(seed);

		if (MT19937_rand() == output)
			break;

		--seed;
	} while (seed != start);

	return seed;
}

int main()
{
	uint32_t output;
	uint32_t seed;

	srand(time(NULL));

	output = get_rng_output();
	printf("Output: 0x%08x\n", output);

	seed = crack_rng_seed(output);
	printf("Seed: 0x%08x\n", seed);
	printf("Real seed: 0x%08x\n", real_seed);

	return 0;
}
