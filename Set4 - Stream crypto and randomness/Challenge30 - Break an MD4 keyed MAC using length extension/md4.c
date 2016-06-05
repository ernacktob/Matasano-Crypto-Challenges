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

int md4_hash(const uint8_t *message, uint64_t ml, uint32_t hh[4])
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

	hh[0] = A;
	hh[1] = B;
	hh[2] = C;
	hh[3] = D;

	free(M);
	return 0;
}

int md4_update(const uint8_t *message, uint64_t ml, const uint32_t prev_hh[4], uint64_t pl, uint32_t hh[4])
{
	uint32_t A = prev_hh[0];
	uint32_t B = prev_hh[1];
	uint32_t C = prev_hh[2];
	uint32_t D = prev_hh[3];

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
	*((uint64_t *)(M + (ml + 8 + rem) / 8)) = pl + ml;

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

	hh[0] = A;
	hh[1] = B;
	hh[2] = C;
	hh[3] = D;

	free(M);
	return 0;
}
