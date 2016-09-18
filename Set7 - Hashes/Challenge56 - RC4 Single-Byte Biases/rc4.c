#include <stdlib.h>
#include <stdint.h>

#include "rc4.h"

static uint8_t S[N];
static int i, j;

static void KSA(const uint8_t *K, size_t l)
{
	uint8_t tmp;

	for (i = 0; i < N; i++)
		S[i] = i;

	j = 0;

	for (i = 0; i < N; i++) {
		j = (j + S[i] + K[i % l]) & 0xff;
		tmp = S[i];
		S[i] = S[j];
		S[j] = tmp;
	}
}

static uint8_t PRGA()
{
	uint8_t tmp;

	i = (i + 1) & 0xff;
	j = (j + S[i]) & 0xff;
	tmp = S[i];
	S[i] = S[j];
	S[j] = tmp;

	return S[(S[i] + S[j]) & 0xff];
}

void rc4_init(const uint8_t *key, size_t len)
{
	KSA(key, len);
	i = 0;
	j = 0;
}

void rc4_process(uint8_t *result, const uint8_t *data, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		result[n] = data[n] ^ PRGA();
}
