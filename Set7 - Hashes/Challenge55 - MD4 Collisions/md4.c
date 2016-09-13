#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

static uint64_t to_big_endian64(uint64_t n)
{
	uint64_t b0, b1, b2, b3, b4, b5, b6, b7;

	b0 = (n & 0xff00000000000000ULL) >> 56;
	b1 = (n & 0x00ff000000000000ULL) >> 40;
	b2 = (n & 0x0000ff0000000000ULL) >> 24;
	b3 = (n & 0x000000ff00000000ULL) >> 8;
	b4 = (n & 0x00000000ff000000ULL) << 8;
	b5 = (n & 0x0000000000ff0000ULL) << 24;
	b6 = (n & 0x000000000000ff00ULL) << 40;
	b7 = (n & 0x00000000000000ffULL) << 56;

	return b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7;
}

static uint32_t left_rotate(uint32_t n, int amount)
{
	return (n << amount) | (n >> (32 - amount));
}

static inline uint32_t F(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (X & Y) | ((~X) & Z);
}

static inline uint32_t G(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (X & Y) | (X & Z) | (Y & Z);
}

static inline uint32_t H(uint32_t X, uint32_t Y, uint32_t Z)
{
	return X ^ Y ^ Z;
}

int md4_hash(const uint8_t *message, uint64_t ml, uint8_t hh[16])
{
	uint32_t A = 0x67452301;
	uint32_t B = 0xefcdab89;
	uint32_t C = 0x98badcfe;
	uint32_t D = 0x10325476;

	uint64_t rem = (512 - ((ml + 8) % 512) + 448) % 512;
	uint64_t N = (ml + 8 + rem + 64) / 32;
	uint8_t *M;

	uint32_t X[16];
	size_t i, j;
	uint32_t AA, BB, CC, DD;

	M = calloc(N * 4, 1);

	if (M == NULL) {
		fprintf(stderr, "Calloc failed. Error: %s\n", strerror(errno));
		return -1;
	}

	memcpy(M, message, ml / 8);
	M[ml / 8] = 0x80;
	*((uint64_t *)(M + (ml + 8 + rem) / 8)) = ml;

	/* Process each 16-word block. */
	for (i = 0; i < N / 16; i++) {

		/* Copy block i into X. */
		for (j = 0; j < 16; j++)
			X[j] = *((uint32_t *)M + i * 16 + j);

		AA = A;
		BB = B;
		CC = C;
		DD = D;

		/* Round 1. */
		A = left_rotate(A + F(B, C, D) + X[0], 3);
		D = left_rotate(D + F(A, B, C) + X[1], 7);
		C = left_rotate(C + F(D, A, B) + X[2], 11);
		B = left_rotate(B + F(C, D, A) + X[3], 19);
		A = left_rotate(A + F(B, C, D) + X[4], 3);
		D = left_rotate(D + F(A, B, C) + X[5], 7);
		C = left_rotate(C + F(D, A, B) + X[6], 11);
		B = left_rotate(B + F(C, D, A) + X[7], 19);
		A = left_rotate(A + F(B, C, D) + X[8], 3);
		D = left_rotate(D + F(A, B, C) + X[9], 7);
		C = left_rotate(C + F(D, A, B) + X[10], 11);
		B = left_rotate(B + F(C, D, A) + X[11], 19);
		A = left_rotate(A + F(B, C, D) + X[12], 3);
		D = left_rotate(D + F(A, B, C) + X[13], 7);
		C = left_rotate(C + F(D, A, B) + X[14], 11);
		B = left_rotate(B + F(C, D, A) + X[15], 19);

		/* Round 2 */
		A = left_rotate(A + G(B, C, D) + X[0] + 0x5a827999, 3);
		D = left_rotate(D + G(A, B, C) + X[4] + 0x5a827999, 5);
		C = left_rotate(C + G(D, A, B) + X[8] + 0x5a827999, 9);
		B = left_rotate(B + G(C, D, A) + X[12] + 0x5a827999, 13);
		A = left_rotate(A + G(B, C, D) + X[1] + 0x5a827999, 3);
		D = left_rotate(D + G(A, B, C) + X[5] + 0x5a827999, 5);
		C = left_rotate(C + G(D, A, B) + X[9] + 0x5a827999, 9);
		B = left_rotate(B + G(C, D, A) + X[13] + 0x5a827999, 13);
		A = left_rotate(A + G(B, C, D) + X[2] + 0x5a827999, 3);
		D = left_rotate(D + G(A, B, C) + X[6] + 0x5a827999, 5);
		C = left_rotate(C + G(D, A, B) + X[10] + 0x5a827999, 9);
		B = left_rotate(B + G(C, D, A) + X[14] + 0x5a827999, 13);
		A = left_rotate(A + G(B, C, D) + X[3] + 0x5a827999, 3);
		D = left_rotate(D + G(A, B, C) + X[7] + 0x5a827999, 5);
		C = left_rotate(C + G(D, A, B) + X[11] + 0x5a827999, 9);
		B = left_rotate(B + G(C, D, A) + X[15] + 0x5a827999, 13);

		/* Round 3 */
		A = left_rotate(A + H(B, C, D) + X[0] + 0x6ed9eba1, 3);
		D = left_rotate(D + H(A, B, C) + X[8] + 0x6ed9eba1, 9);
		C = left_rotate(C + H(D, A, B) + X[4] + 0x6ed9eba1, 11);
		B = left_rotate(B + H(C, D, A) + X[12] + 0x6ed9eba1, 15);
		A = left_rotate(A + H(B, C, D) + X[2] + 0x6ed9eba1, 3);
		D = left_rotate(D + H(A, B, C) + X[10] + 0x6ed9eba1, 9);
		C = left_rotate(C + H(D, A, B) + X[6] + 0x6ed9eba1, 11);
		B = left_rotate(B + H(C, D, A) + X[14] + 0x6ed9eba1, 15);
		A = left_rotate(A + H(B, C, D) + X[1] + 0x6ed9eba1, 3);
		D = left_rotate(D + H(A, B, C) + X[9] + 0x6ed9eba1, 9);
		C = left_rotate(C + H(D, A, B) + X[5] + 0x6ed9eba1, 11);
		B = left_rotate(B + H(C, D, A) + X[13] + 0x6ed9eba1, 15);
		A = left_rotate(A + H(B, C, D) + X[3] + 0x6ed9eba1, 3);
		D = left_rotate(D + H(A, B, C) + X[11] + 0x6ed9eba1, 9);
		C = left_rotate(C + H(D, A, B) + X[7] + 0x6ed9eba1, 11);
		B = left_rotate(B + H(C, D, A) + X[15] + 0x6ed9eba1, 15);

		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}

	((uint32_t *)hh)[0] = A;
	((uint32_t *)hh)[1] = B;
	((uint32_t *)hh)[2] = C;
	((uint32_t *)hh)[3] = D;

	free(M);
	return 0;
}

#define collect_chaining_vars(i) do {a[i] = A; b[i] = B; c[i] = C; d[i] = D;} while (0)

void md4_get_chaining_variables(const uint8_t block[64], uint32_t a[13], uint32_t b[13], uint32_t c[13], uint32_t d[13])
{
	uint32_t A = 0x67452301;
	uint32_t B = 0xefcdab89;
	uint32_t C = 0x98badcfe;
	uint32_t D = 0x10325476;

	uint32_t X[16];
	size_t j;
	uint32_t AA, BB, CC, DD;

	/* Copy block into X. */
	for (j = 0; j < 16; j++)
		X[j] = *((uint32_t *)block + j);

	AA = A;
	BB = B;
	CC = C;
	DD = D;
	collect_chaining_vars(0);

	/* Round 1. */
	A = left_rotate(A + F(B, C, D) + X[0], 3);
	D = left_rotate(D + F(A, B, C) + X[1], 7);
	C = left_rotate(C + F(D, A, B) + X[2], 11);
	B = left_rotate(B + F(C, D, A) + X[3], 19);
	collect_chaining_vars(1);

	A = left_rotate(A + F(B, C, D) + X[4], 3);
	D = left_rotate(D + F(A, B, C) + X[5], 7);
	C = left_rotate(C + F(D, A, B) + X[6], 11);
	B = left_rotate(B + F(C, D, A) + X[7], 19);
	collect_chaining_vars(2);

	A = left_rotate(A + F(B, C, D) + X[8], 3);
	D = left_rotate(D + F(A, B, C) + X[9], 7);
	C = left_rotate(C + F(D, A, B) + X[10], 11);
	B = left_rotate(B + F(C, D, A) + X[11], 19);
	collect_chaining_vars(3);

	A = left_rotate(A + F(B, C, D) + X[12], 3);
	D = left_rotate(D + F(A, B, C) + X[13], 7);
	C = left_rotate(C + F(D, A, B) + X[14], 11);
	B = left_rotate(B + F(C, D, A) + X[15], 19);
	collect_chaining_vars(4);

	/* Round 2 */
	A = left_rotate(A + G(B, C, D) + X[0] + 0x5a827999, 3);
	D = left_rotate(D + G(A, B, C) + X[4] + 0x5a827999, 5);
	C = left_rotate(C + G(D, A, B) + X[8] + 0x5a827999, 9);
	B = left_rotate(B + G(C, D, A) + X[12] + 0x5a827999, 13);
	collect_chaining_vars(5);

	A = left_rotate(A + G(B, C, D) + X[1] + 0x5a827999, 3);
	D = left_rotate(D + G(A, B, C) + X[5] + 0x5a827999, 5);
	C = left_rotate(C + G(D, A, B) + X[9] + 0x5a827999, 9);
	B = left_rotate(B + G(C, D, A) + X[13] + 0x5a827999, 13);
	collect_chaining_vars(6);

	A = left_rotate(A + G(B, C, D) + X[2] + 0x5a827999, 3);
	D = left_rotate(D + G(A, B, C) + X[6] + 0x5a827999, 5);
	C = left_rotate(C + G(D, A, B) + X[10] + 0x5a827999, 9);
	B = left_rotate(B + G(C, D, A) + X[14] + 0x5a827999, 13);
	collect_chaining_vars(7);

	A = left_rotate(A + G(B, C, D) + X[3] + 0x5a827999, 3);
	D = left_rotate(D + G(A, B, C) + X[7] + 0x5a827999, 5);
	C = left_rotate(C + G(D, A, B) + X[11] + 0x5a827999, 9);
	B = left_rotate(B + G(C, D, A) + X[15] + 0x5a827999, 13);
	collect_chaining_vars(8);

	/* Round 3 */
	A = left_rotate(A + H(B, C, D) + X[0] + 0x6ed9eba1, 3);
	D = left_rotate(D + H(A, B, C) + X[8] + 0x6ed9eba1, 9);
	C = left_rotate(C + H(D, A, B) + X[4] + 0x6ed9eba1, 11);
	B = left_rotate(B + H(C, D, A) + X[12] + 0x6ed9eba1, 15);
	collect_chaining_vars(9);

	A = left_rotate(A + H(B, C, D) + X[2] + 0x6ed9eba1, 3);
	D = left_rotate(D + H(A, B, C) + X[10] + 0x6ed9eba1, 9);
	C = left_rotate(C + H(D, A, B) + X[6] + 0x6ed9eba1, 11);
	B = left_rotate(B + H(C, D, A) + X[14] + 0x6ed9eba1, 15);
	collect_chaining_vars(10);

	A = left_rotate(A + H(B, C, D) + X[1] + 0x6ed9eba1, 3);
	D = left_rotate(D + H(A, B, C) + X[9] + 0x6ed9eba1, 9);
	C = left_rotate(C + H(D, A, B) + X[5] + 0x6ed9eba1, 11);
	B = left_rotate(B + H(C, D, A) + X[13] + 0x6ed9eba1, 15);
	collect_chaining_vars(11);

	A = left_rotate(A + H(B, C, D) + X[3] + 0x6ed9eba1, 3);
	D = left_rotate(D + H(A, B, C) + X[11] + 0x6ed9eba1, 9);
	C = left_rotate(C + H(D, A, B) + X[7] + 0x6ed9eba1, 11);
	B = left_rotate(B + H(C, D, A) + X[15] + 0x6ed9eba1, 15);
	collect_chaining_vars(12);
}
