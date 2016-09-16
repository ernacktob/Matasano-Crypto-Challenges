#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "md4.h"

#define BLOCK_SIZE	64
#define HASH_LENGTH	16

#define BIT(A, i)	(((A) >> ((i) - 1)) & 0x1)

#define F(X, Y, Z)	(((X) & (Y)) | ((~(X)) & (Z)))
#define G(X, Y, Z)	(((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define H(X, Y, Z)	((X) ^ (Y) ^ (Z))

#define RROT(X, i)	(((X) >> (i)) | ((X) << (32 - (i))))
#define LROT(X, i)	(((X) << (i)) | ((X) >> (32 - (i))))

#define K1		0x5a827999
#define K2		0x6ed9eba1

static int attempts = 0;

static inline void print_hexstr(const uint8_t *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", bytes[i]);
}

static void single_step_modification(uint32_t m[BLOCK_SIZE / 4], uint32_t a[13], uint32_t b[13], uint32_t c[13], uint32_t d[13])
{
	a[1] = a[1] ^ ((BIT(a[1], 7) ^ BIT(b[0], 7)) << 6);
	m[0] = RROT(a[1], 3) - a[0] - F(b[0], c[0], d[0]);

	d[1] = d[1] ^ (BIT(d[1], 7) << 6) ^ ((BIT(d[1], 8) ^ BIT(a[1], 8)) << 7) ^ ((BIT(d[1], 11) ^ BIT(a[1], 11)) << 10);
	d[1] = d[1] ^ (BIT(d[1], 1) << 0);		/* extra conditions for a_(6, 29) */
	d[1] = d[1] ^ ((BIT(d[1], 2) ^ 1) << 1);	/* extra conditions for a_(6, 30) */
	d[1] = d[1] ^ (BIT(d[1], 4) << 3);		/* extra conditions for a_(6, 32) */
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);

	c[1] = c[1] ^ ((BIT(c[1], 7) ^ 1) << 6) ^ ((BIT(c[1], 8) ^ 1) << 7) ^ (BIT(c[1], 11) << 10) ^ ((BIT(c[1], 26) ^ BIT(d[1], 26)) << 25);
	c[1] = c[1] ^ (BIT(c[1], 1) << 0);	/* extra conditions for a_(6, 29) */
	c[1] = c[1] ^ (BIT(c[1], 2) << 1);	/* extra conditions for a_(6, 30) */
	c[1] = c[1] ^ (BIT(c[1], 4) << 3);	/* extra conditions for a_(6, 32) */
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);

	b[1] = b[1] ^ ((BIT(b[1], 7) ^ 1) << 6) ^ (BIT(b[1], 8) << 7) ^ (BIT(b[1], 11) << 10) ^ (BIT(b[1], 26) << 25);
	b[1] = b[1] ^ ((BIT(b[1], 23) ^ BIT(c[1], 23)) << 22);	/* extra condition for c_(5, 29) */
	b[1] = b[1] ^ ((BIT(b[1], 1) ^ 1) << 0);	/* extra conditions for a_(6, 29) */
	b[1] = b[1] ^ ((BIT(b[1], 2) ^ 1) << 1);	/* extra conditions for a_(6, 30) */
	b[1] = b[1] ^ ((BIT(b[1], 4) ^ 1) << 3);	/* extra conditions for a_(6, 32) */
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);


	a[2] = a[2] ^ ((BIT(a[2], 8) ^ 1) << 7) ^ ((BIT(a[2], 11) ^ 1) << 10) ^ (BIT(a[2], 26) << 25) ^ ((BIT(a[2], 14) ^ BIT(b[1], 14)) << 13);
	a[2] = a[2] ^ (BIT(a[2], 17) << 16);	/* extra conditions for d_(5, 19) */
	a[2] = a[2] ^ (BIT(a[2], 24) << 23);	/* extra conditions for d_(5, 26) */
	a[2] = a[2] ^ (BIT(a[2], 25) << 24);	/* extra conditions for d_(5, 27) */
	a[2] = a[2] ^ (BIT(a[2], 27) << 26);	/* extra conditions for d_(5, 29) */
	a[2] = a[2] ^ (BIT(a[2], 30) << 29);	/* extra conditions for d_(5, 32) */
	a[2] = a[2] ^ ((BIT(a[2], 23) ^ 1) << 22);	/* extra condition for c_(5, 29) */
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);

	d[2] = d[2] ^ (BIT(d[2], 14) << 13) ^ ((BIT(d[2], 19) ^ BIT(a[2], 19)) << 18) ^ ((BIT(d[2], 20) ^ BIT(a[2], 20)) << 19) ^ \
	       ((BIT(d[2], 21) ^ BIT(a[2], 21)) << 20) ^ ((BIT(d[2], 22) ^ BIT(a[2], 22)) << 21) ^ ((BIT(d[2], 26) ^ 1) << 25);
	d[2] = d[2] ^ ((BIT(d[2], 17) ^ 1) << 16);	/* extra conditions for c_(5, 26) */
	d[2] = d[2] ^ ((BIT(d[2], 18) ^ 1) << 17);	/* extra conditions for c_(5, 27) */
	d[2] = d[2] ^ (BIT(d[2], 23) << 22);		/* extra condition for c_(5, 29) */
	d[2] = d[2] ^ (BIT(d[2], 31) << 30);		/* extra conditions for d_(6, 29) */
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);

	c[2] = c[2] ^ ((BIT(c[2], 13) ^ BIT(d[2], 13)) << 12) ^ (BIT(c[2], 14) << 13) ^ ((BIT(c[2], 15) ^ BIT(d[2], 15)) << 14) ^ \
	       (BIT(c[2], 19) << 18) ^ (BIT(c[2], 20) << 19) ^ ((BIT(c[2], 21) ^ 1) << 20) ^ (BIT(c[2], 22) << 21);
	c[2] = c[2] ^ (BIT(c[2], 17) << 16);	/* extra conditions for c_(5, 26) */
	c[2] = c[2] ^ (BIT(c[2], 18) << 17);	/* extra conditions for c_(5, 27) */
	c[2] = c[2] ^ ((BIT(c[2], 23) ^ 1) << 22);	/* extra condition for c_(5, 29) */
	c[2] = c[2] ^ (BIT(c[2], 31) << 30);	/* extra conditions for d_(6, 29) */
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);

	b[2] = b[2] ^ ((BIT(b[2], 13) ^ 1) << 12) ^ ((BIT(b[2], 14) ^ 1) << 13) ^ (BIT(b[2], 15) << 14) ^ ((BIT(b[2], 17) ^ BIT(c[2], 17)) << 16) ^ \
	       (BIT(b[2], 19) << 18) ^ (BIT(b[2], 20) << 19) ^ (BIT(b[2], 21) << 20) ^ (BIT(b[2], 22) << 21);
	b[2] = b[2] ^ (BIT(b[2], 18) << 17);	/* extra conditions for c_(5, 27) */
	b[2] = b[2] ^ ((BIT(b[2], 31) ^ 1) << 30);	/* extra conditions for d_(6, 29) */
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);


	a[3] = a[3] ^ ((BIT(a[3], 13) ^ 1) << 12) ^ ((BIT(a[3], 14) ^ 1) << 13) ^ ((BIT(a[3], 15) ^ 1) << 14) ^ (BIT(a[3], 17) << 16) ^ \
	       (BIT(a[3], 19) << 18) ^ (BIT(a[3], 20) << 19) ^ (BIT(a[3], 21) << 20) ^ ((BIT(a[3], 23) ^ BIT(b[2], 23)) << 22) ^ \
	       ((BIT(a[3], 22) ^ 1) << 21) ^ ((BIT(a[3], 26) ^ BIT(b[2], 26)) << 25);
	a[3] = a[3] ^ ((BIT(a[3], 27) ^ BIT(b[2], 27)) << 26);	/* extra conditions for c_(6, 29) */
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	d[3] = d[3] ^ ((BIT(d[3], 13) ^ 1) << 12) ^ ((BIT(d[3], 14) ^ 1) << 13) ^ ((BIT(d[3], 15) ^ 1) << 14) ^ (BIT(d[3], 17) << 16) ^ \
	       (BIT(d[3], 20) << 19) ^ ((BIT(d[3], 21) ^ 1) << 20) ^ ((BIT(d[3], 22) ^ 1) << 21) ^ (BIT(d[3], 23) << 22) ^ \
	       ((BIT(d[3], 26) ^ 1) << 25) ^ ((BIT(d[3], 30) ^ BIT(a[3], 30)) << 29);
	d[3] = d[3] ^ ((BIT(d[3], 16) ^ 1) << 15);	/* extra condition for b_(5, 29) */
	d[3] = d[3] ^ (BIT(d[3], 19) << 18);	/* extra condition for b_(5, 32) */
	d[3] = d[3] ^ (BIT(d[3], 27) << 26);	/* extra conditions for c_(6, 29) */
	m[9] = RROT(d[3], 7) - d[2] - F(a[3], b[2], c[2]);

	c[3] = c[3] ^ ((BIT(c[3], 17) ^ 1) << 16) ^ (BIT(c[3], 20) << 19) ^ (BIT(c[3], 21) << 20) ^ (BIT(c[3], 22) << 21) ^ (BIT(c[3], 23) << 22) ^ \
	       (BIT(c[3], 26) << 25) ^ ((BIT(c[3], 30) ^ 1) << 29) ^ ((BIT(c[3], 32) ^ BIT(d[3], 32)) << 31);
	c[3] = c[3] ^ (BIT(c[3], 16) << 15);	/* extra condition for b_(5, 29) */
	c[3] = c[3] ^ ((BIT(c[3], 19) ^ 1) << 18);	/* extra condition for b_(5, 32) */
	c[3] = c[3] ^ (BIT(c[3], 27) << 26);	/* extra conditions for c_(6, 29) */
	m[10] = RROT(c[3], 11) - c[2] - F(d[3], a[3], b[2]);

	b[3] = b[3] ^ (BIT(b[3], 20) << 19) ^ ((BIT(b[3], 21) ^ 1) << 20) ^ ((BIT(b[3], 22) ^ 1) << 21) ^ ((BIT(b[3], 23) ^ BIT(c[3], 23)) << 22) ^ \
	       ((BIT(b[3], 26) ^ 1) << 25) ^ (BIT(b[3], 30) << 29) ^ (BIT(b[3], 32) << 31);
	b[3] = b[3] ^ (BIT(b[3], 16) << 15);	/* extra condition for b_(5, 29) */
	b[3] = b[3] ^ ((BIT(b[3], 17) ^ 1) << 16);	/* extra condition for b_(5, 30) */
	b[3] = b[3] ^ (BIT(b[3], 19) << 18);	/* extra condition for b_(5, 32) */
	b[3] = b[3] ^ ((BIT(b[3], 27) ^ 1) << 26);	/* extra conditions for c_(6, 29) */
	m[11] = RROT(b[3], 19) - b[2] - F(c[3], d[3], a[3]);


	a[4] = a[4] ^ (BIT(a[4], 23) << 22) ^ (BIT(a[4], 26) << 25) ^ ((BIT(a[4], 27) ^ BIT(b[3], 27)) << 26) ^ ((BIT(a[4], 29) ^ BIT(b[3], 29)) << 28) ^ \
	       ((BIT(a[4], 30) ^ 1) << 29) ^ (BIT(a[4], 32) << 31);
	a[4] = a[4] ^ ((BIT(a[4], 20) ^ 1) << 19);	/* extra condition for c_(5, 29) */
	a[4] = a[4] ^ (BIT(a[4], 16) << 15);	/* extra condition for b_(5, 29) */
	a[4] = a[4] ^ (BIT(a[4], 17) << 16);	/* extra condition for b_(5, 30) */
	a[4] = a[4] ^ (BIT(a[4], 19) << 18);	/* extra condition for b_(5, 32) */
	m[12] = RROT(a[4], 3) - a[3] - F(b[3], c[3], d[3]);

	d[4] = d[4] ^ (BIT(d[4], 23) << 22) ^ (BIT(d[4], 26) << 25) ^ ((BIT(d[4], 27) ^ 1) << 26) ^ ((BIT(d[4], 29) ^ 1) << 28) ^ (BIT(d[4], 30) << 29) ^ \
	       ((BIT(d[4], 32) ^ 1) << 31);
	d[4] = d[4] ^ ((BIT(d[4], 20) ^ BIT(a[4], 20)) << 19);	/* extra condition for c_(5, 29) */
	d[4] = d[4] ^ ((BIT(d[4], 16) ^ 1) << 15);	/* extra condition for b_(5, 29) */
	d[4] = d[4] ^ ((BIT(d[4], 17) ^ 1) << 16);	/* extra condition for b_(5, 30) */
	d[4] = d[4] ^ ((BIT(d[4], 19) ^ 1) << 18);	/* extra condition for b_(5, 32) */
	m[13] = RROT(d[4], 7) - d[3] - F(a[4], b[3], c[3]);

	c[4] = c[4] ^ ((BIT(c[4], 19) ^ BIT(d[4], 19)) << 18) ^ ((BIT(c[4], 23) ^ 1) << 22) ^ ((BIT(c[4], 26) ^ 1) << 25) ^ (BIT(c[4], 27) << 26) ^ \
	       (BIT(c[4], 29) << 28) ^ (BIT(c[4], 30) << 29);
	c[4] = c[4] ^ (BIT(c[4], 20) << 19);	/* extra condition for c_(5, 29) */
	m[14] = RROT(c[4], 11) - c[3] - F(d[4], a[4], b[3]);

	b[4] = b[4] ^ (BIT(b[4], 19) << 18) ^ ((BIT(b[4], 26) ^ 1) << 25) ^ ((BIT(b[4], 27) ^ 1) << 26) ^ ((BIT(b[4], 29) ^ 1) << 28) ^ (BIT(b[4], 30) << 29) ^ \
	       ((BIT(b[4], 32) ^ BIT(c[4], 32)) << 31);
	b[4] = b[4] ^ ((BIT(b[4], 20) ^ BIT(d[4], 20)) << 19);	/* extra condition for c_(5, 29) */
	m[15] = RROT(b[4], 19) - b[3] - F(c[4], d[4], a[4]);
}

static void multi_step_modification(uint32_t m[BLOCK_SIZE / 4], uint32_t a[13], uint32_t b[13], uint32_t c[13], uint32_t d[13])
{
	/* Correct a_(5, i) for i = 19, 26, 27, 29, 32 */
	a[5] = a[5] ^ ((BIT(a[5], 19) ^ BIT(c[4], 19)) << 18);
	m[0] = RROT(a[5], 3) - a[4] - K1 - G(b[4], c[4], d[4]);
	a[1] = LROT(a[0] + F(b[0], c[0], d[0]) + m[0], 3);
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);
	
	a[5] = a[5] ^ ((BIT(a[5], 26) ^ 1) << 25);
	m[0] = RROT(a[5], 3) - a[4] - K1 - G(b[4], c[4], d[4]);
	a[1] = LROT(a[0] + F(b[0], c[0], d[0]) + m[0], 3);
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);

	a[5] = a[5] ^ (BIT(a[5], 27) << 26);
	m[0] = RROT(a[5], 3) - a[4] - K1 - G(b[4], c[4], d[4]);
	a[1] = LROT(a[0] + F(b[0], c[0], d[0]) + m[0], 3);
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);

	a[5] = a[5] ^ ((BIT(a[5], 29) ^ 1) << 28);
	m[0] = RROT(a[5], 3) - a[4] - K1 - G(b[4], c[4], d[4]);
	a[1] = LROT(a[0] + F(b[0], c[0], d[0]) + m[0], 3);
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);

	a[5] = a[5] ^ ((BIT(a[5], 32) ^ 1) << 31);
	m[0] = RROT(a[5], 3) - a[4] - K1 - G(b[4], c[4], d[4]);
	a[1] = LROT(a[0] + F(b[0], c[0], d[0]) + m[0], 3);
	m[1] = RROT(d[1], 7) - d[0] - F(a[1], b[0], c[0]);
	m[2] = RROT(c[1], 11) - c[0] - F(d[1], a[1], b[0]);
	m[3] = RROT(b[1], 19) - b[0] - F(c[1], d[1], a[1]);
	m[4] = RROT(a[2], 3) - a[1] - F(b[1], c[1], d[1]);

	/* These variables get affected by corrections of a[5]. */
	d[5] = LROT(d[4] + G(a[5], b[4], c[4]) + K1 + m[4], 5);
	c[5] = LROT(c[4] + G(d[5], a[5], b[4]) + K1 + m[8], 9);
	b[5] = LROT(b[4] + G(c[5], d[5], a[5]) + K1 + m[12], 13);
	a[6] = LROT(a[5] + G(b[5], c[5], d[5]) + K1 + m[1], 3);
	d[6] = LROT(d[5] + G(a[6], b[5], c[5]) + K1 + m[5], 5);
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	/* Correct d_(5, i) for i = 19, 26, 27, 29, 32. */
	d[5] = d[5] ^ ((BIT(d[5], 19) ^ BIT(a[5], 19)) << 18);
	m[4] = RROT(d[5], 5) - d[4] - K1 - G(a[5], b[4], c[4]);
	a[2] = LROT(a[1] + F(b[1], c[1], d[1]) + m[4], 3);
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	d[5] = d[5] ^ ((BIT(d[5], 26) ^ BIT(b[4], 26)) << 25);
	m[4] = RROT(d[5], 5) - d[4] - K1 - G(a[5], b[4], c[4]);
	a[2] = LROT(a[1] + F(b[1], c[1], d[1]) + m[4], 3);
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	d[5] = d[5] ^ ((BIT(d[5], 27) ^ BIT(b[4], 27)) << 26);
	m[4] = RROT(d[5], 5) - d[4] - K1 - G(a[5], b[4], c[4]);
	a[2] = LROT(a[1] + F(b[1], c[1], d[1]) + m[4], 3);
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	d[5] = d[5] ^ ((BIT(d[5], 29) ^ BIT(b[4], 29)) << 28);
	m[4] = RROT(d[5], 5) - d[4] - K1 - G(a[5], b[4], c[4]);
	a[2] = LROT(a[1] + F(b[1], c[1], d[1]) + m[4], 3);
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	d[5] = d[5] ^ ((BIT(d[5], 32) ^ BIT(b[4], 32)) << 31);
	m[4] = RROT(d[5], 5) - d[4] - K1 - G(a[5], b[4], c[4]);
	a[2] = LROT(a[1] + F(b[1], c[1], d[1]) + m[4], 3);
	m[5] = RROT(d[2], 7) - d[1] - F(a[2], b[1], c[1]);
	m[6] = RROT(c[2], 11) - c[1] - F(d[2], a[2], b[1]);
	m[7] = RROT(b[2], 19) - b[1] - F(c[2], d[2], a[2]);
	m[8] = RROT(a[3], 3) - a[2] - F(b[2], c[2], d[2]);

	/* These variables get affected by corrections of d[5]. */
	c[5] = LROT(c[4] + G(d[5], a[5], b[4]) + K1 + m[8], 9);
	b[5] = LROT(b[4] + G(c[5], d[5], a[5]) + K1 + m[12], 13);
	a[6] = LROT(a[5] + G(b[5], c[5], d[5]) + K1 + m[1], 3);
	d[6] = LROT(d[5] + G(a[6], b[5], c[5]) + K1 + m[5], 5);
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	if (BIT(c[5], 26) != BIT(d[5], 26)) {
		m[5] = m[5] - (1 << 9);
		d[2] = d[2] ^ (BIT(d[2], 17) << 16);

		/* This condition cannot be guaranteed... */
		if (BIT(a[2], 17) != BIT(b[1], 17)) {
			if (BIT(a[2], 17) == 0)
				m[6] = m[6] - (1 << 16);
			else
				m[6] = m[6] + (1 << 16);
		}

		m[8] = m[8] + (1 << 16);
		m[9] = m[9] + (1 << 16);
		c[5] = c[5] ^ ((BIT(c[5], 26) ^ 1) << 25);
	}

	if (BIT(c[5], 27) != BIT(d[5], 27)) {
		m[5] = m[5] - (1 << 10);
		d[2] = d[2] ^ (BIT(d[2], 18) << 17);

		if (BIT(a[2], 18) != BIT(b[1], 18)) {
			if (BIT(a[2], 18) == 0)
				m[6] = m[6] - (1 << 17);
			else
				m[6] = m[6] + (1 << 17);
		}

		m[8] = m[8] + (1 << 17);
		m[9] = m[9] + (1 << 17);
		c[5] = c[5] ^ ((BIT(c[5], 27) ^ 1) << 26);
	}

	if (BIT(c[5], 29) != BIT(d[5], 29)) {
		c[4] = c[4] ^ ((BIT(c[4], 20) ^ 1) << 19);
		m[14] = RROT(c[4], 11) - c[3] - F(d[4], a[4], b[3]);

		if (BIT(a[5], 20) != BIT(b[4], 20)) {
			m[4] = m[4] - (1 << 19);
			a[2] = a[2] ^ (BIT(a[2], 23) << 22);
			m[8] = m[8] + (1 << 22);
		}

		c[5] = c[5] ^ ((BIT(c[5], 29) ^ 1) << 28);
	}

	/* XXX Implement c_(5, 30), c_(5, 32). */

	/* These variables get affected by correction of c[5]. */
	c[5] = LROT(c[4] + G(d[5], a[5], b[4]) + K1 + m[8], 9);	/* the c5 correction can have carries after c_(5, 29). */
	b[5] = LROT(b[4] + G(c[5], d[5], a[5]) + K1 + m[12], 13);
	a[6] = LROT(a[5] + G(b[5], c[5], d[5]) + K1 + m[1], 3);
	d[6] = LROT(d[5] + G(a[6], b[5], c[5]) + K1 + m[5], 5);
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	/* From here below are more advanced modifications
	 * that I found by hand analysis. */

	if (BIT(b[5], 29) != 1) {
		m[11] = m[11] + (1 << 28);
		b[3] = b[3] ^ ((BIT(b[3], 16) ^ 1) << 15);
		m[12] = m[12] + (1 << 15);
		m[15] = m[15] - (1 << 15);
		b[5] = b[5] ^ ((BIT(b[5], 29) ^ 1) << 28);
	}

	if (BIT(b[5], 30) != 1) {
		m[11] = m[11] - (1 << 29);
		b[3] = b[3] ^ (BIT(b[3], 17) << 16);
		m[12] = m[12] + (1 << 16);
		m[15] = m[15] + (1 << 16);
		b[5] = b[5] ^ ((BIT(b[5], 30) ^ 1) << 29);
	}

	if (BIT(b[5], 32) != 0) {
		m[11] = m[11] + (1U << 31);
		b[3] = b[3] ^ ((BIT(b[3], 19) ^ 1) << 18);
		m[12] = m[12] - (1 << 18);
		m[15] = m[15] - (1 << 18);
		b[5] = b[5] ^ (BIT(b[5], 32) << 31);
	}

	/* These variables get affected by correction of b[5]. */
	a[6] = LROT(a[5] + G(b[5], c[5], d[5]) + K1 + m[1], 3);
	d[6] = LROT(d[5] + G(a[6], b[5], c[5]) + K1 + m[5], 5);
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	if (BIT(a[6], 29) != 1) {
		m[1] = m[1] + (1 << 25);
		d[1] = d[1] ^ ((BIT(d[1], 1) ^ 1) << 0);

		/* This condition is not always satisfied. When not,
		 * need to update m[2] instead to preserve c[1]. */
		if (BIT(a[1], 1) != BIT(b[0], 1))
			m[2] = m[2] + (1 << 0);

		m[5] = m[5] - (1 << 0);
		a[6] = a[6] ^ ((BIT(a[6], 29) ^ 1) << 28);
	}

	/* This condition was not listed in Wang's paper. */
	if (BIT(a[6], 30) != 0) {
		m[1] = m[1] - (1 << 26);
		d[1] = d[1] ^ (BIT(d[1], 2) << 1);

		/* This condition is not always satisfied. When not,
		 * need to update m[2] instead to preserve c[1]. */
		if (BIT(a[1], 2) != BIT(b[0], 2))
			m[2] = m[2] + (1 << 1);

		m[5] = m[5] + (1 << 1);
		a[6] = a[6] ^ (BIT(a[6], 30) << 29);
	}

	if (BIT(a[6], 32) != 1) {
		m[1] = m[1] + (1 << 28);
		d[1] = d[1] ^ ((BIT(d[1], 4) ^ 1) << 3);

		if (BIT(a[1], 4) != BIT(b[0], 4))
			m[2] = m[2] + (1 << 3);

		m[5] = m[5] - (1 << 3);
		a[6] = a[6] ^ ((BIT(a[6], 32) ^ 1) << 31);
	}

	/* These variables get affected by correction of a[6]. */
	d[6] = LROT(d[5] + G(a[6], b[5], c[5]) + K1 + m[5], 5);
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	if (BIT(d[6], 29) != BIT(b[5], 29)) {
		m[5] = m[5] + (1 << 23);
		d[2] = d[2] ^ ((BIT(d[2], 31) ^ 1) << 30);

		if (BIT(a[2], 31) != BIT(b[1], 31)) {
			if (BIT(a[2], 31) == 0)
				m[6] = m[6] + (1 << 30);
			else
				m[6] = m[6] - (1 << 30);
		}

		m[9] = m[9] - (1 << 30);
		d[6] = d[6] ^ ((BIT(d[6], 29) ^ 1) << 28);
	}

	/* These variables get affected by correction of a[6]. */
	c[6] = LROT(c[5] + G(d[6], a[6], b[5]) + K1 + m[9], 9);

	if (BIT(c[6], 29) != BIT(d[6], 29)) {
		m[9] = m[9] + (1 << 19);
		d[3] = d[3] ^ ((BIT(d[3], 27) ^ 1) << 26);
		m[13] = m[13] - (1 << 26);
		c[6] = c[6] ^ ((BIT(c[6], 29) ^ 1) << 28);
	}

	/* XXX Correct c_(6, 30), c_(6, 32) ? */
	/* There are currently 6 bits in total that are not corrected.
	 * So the probability of finding a collision is 2^(-6). */
}

void check(uint32_t m[BLOCK_SIZE / 4])
{
	uint32_t a[13], b[13], c[13], d[13];	/* chaining variables for each step. */
	md4_get_chaining_variables((uint8_t *)m, a, b, c, d);

	if (BIT(a[1], 7) != BIT(b[0], 7))
		printf("a[1] broken\n");
	
	if (BIT(d[1], 7) != 0 || BIT(d[1], 8) != BIT(a[1], 8) || BIT(d[1], 11) != BIT(a[1], 11))
		printf("d[1] broken\n");

	if (BIT(c[1], 7) != 1 || BIT(c[1], 8) != 1 || BIT(c[1], 11) != 0 || BIT(c[1], 26) != BIT(d[1], 26))
		printf("c[1] broken\n");

	if (BIT(b[1], 7) != 1 || BIT(b[1], 8) != 0 || BIT(b[1], 11) != 0 || BIT(b[1], 26) != 0)
		printf("b[1] broken\n");
	
	if (BIT(a[2], 8) != 1 || BIT(a[2], 11) != 1 || BIT(a[2], 26) != 0 || BIT(a[2], 14) != BIT(b[1], 14))
		printf("a[2] broken\n");

	if (BIT(d[2], 14) != 0 || BIT(d[2], 19) != BIT(a[2], 19) || BIT(d[2], 20) != BIT(a[2], 20) ||
			BIT(d[2], 21) != BIT(a[2], 21) || BIT(d[2], 22) != BIT(a[2], 22) || BIT(d[2], 26) != 1)
		printf("d[2] broken\n");
	
	if (BIT(c[2], 13) != BIT(d[2], 13) || BIT(c[2], 14) != 0 || BIT(c[2], 15) != BIT(d[2], 15) ||
			BIT(c[2], 19) != 0 || BIT(c[2], 20) != 0 || BIT(c[2], 21) != 1 || BIT(c[2], 22) != 0)
		printf("c[2] broken\n");

	if (BIT(b[2], 13) != 1 || BIT(b[2], 14) != 1 || BIT(b[2], 15) != 0 || BIT(b[2], 17) != BIT(c[2], 17)
			|| BIT(b[2], 19) != 0 || BIT(b[2], 20) != 0 || BIT(b[2], 21) != 0 || BIT(b[2], 22) != 0)
		printf("b[2] broken\n");

	if (BIT(a[3], 13) != 1 || BIT(a[3], 14) != 1 || BIT(a[3], 15) != 1 || BIT(a[3], 17) != 0 || BIT(a[3], 19) != 0
			|| BIT(a[3], 20) != 0 || BIT(a[3], 21) != 0 || BIT(a[3], 23) != BIT(b[2], 23)
			|| BIT(a[3], 22) != 1 || BIT(a[3], 26) != BIT(b[2], 26))
		printf("a[3] broken\n");

	if (BIT(d[3], 13) != 1 || BIT(d[3], 14) != 1 || BIT(d[3], 15) != 1 || BIT(d[3], 17) != 0 || BIT(d[3], 20) != 0
			|| BIT(d[3], 21) != 1 || BIT(d[3], 22) != 1 || BIT(d[3], 23) != 0
			|| BIT(d[3], 26) != 1 || BIT(d[3], 30) != BIT(a[3], 30))
		printf("d[3] broken\n");

	if (BIT(c[3], 17) != 1 || BIT(c[3], 20) != 0 || BIT(c[3], 21) != 0 || BIT(c[3], 22) != 0 || BIT(c[3], 23) != 0
			|| BIT(c[3], 26) != 0 || BIT(c[3], 30) != 1 || BIT(c[3], 32) != BIT(d[3], 32))
		printf("c[3] broken\n");

	if (BIT(b[3], 20) != 0 || BIT(b[3], 21) != 1 || BIT(b[3], 22) != 1 || BIT(b[3], 23) != BIT(c[3], 23) ||
			BIT(b[3], 26) != 1 || BIT(b[3], 30) != 0 || BIT(b[3], 32) != 0)
		printf("b[3] broken\n");

	if (BIT(a[4], 23) != 0 || BIT(a[4], 26) != 0 || BIT(a[4], 27) != BIT(b[3], 27) ||
			BIT(a[4], 29) != BIT(b[3], 29) || BIT(a[4], 30) != 1 || BIT(a[4], 32) != 0)
		printf("a[4] broken\n");

	if (BIT(d[4], 23) != 0 || BIT(d[4], 26) != 0 || BIT(d[4], 27) != 1 || BIT(d[4], 29) != 1
			|| BIT(d[4], 30) != 0 || BIT(d[4], 32) != 1)
		printf("d[4] broken\n");

	if (BIT(c[4], 19) != BIT(d[4], 19) || BIT(c[4], 23) != 1 || BIT(c[4], 26) != 1 || BIT(c[4], 27) != 0 ||
			BIT(c[4], 29) != 0 || BIT(c[4], 30) != 0)
		printf("c[4] broken\n");

	if (BIT(b[4], 19) != 0 || BIT(b[4], 26) != BIT(c[4], 26) || BIT(b[4], 27) != 1 || BIT(b[4], 29) != 1 ||
			BIT(b[4], 30) != 0 || BIT(b[4], 32) != BIT(c[4], 32))
		printf("b[4] broken\n");

	if (BIT(a[5], 19) != BIT(c[4], 19) || BIT(a[5], 26) != 1 || BIT(a[5], 27) != 0 || BIT(a[5], 29) != 1 ||
			BIT(a[5], 32) != 1)
		printf("a[5] broken\n");

	if (BIT(d[5], 19) != BIT(a[5], 19) || BIT(d[5], 26) != BIT(b[4], 26) || BIT(d[5], 27) != BIT(b[4], 27) ||
			BIT(d[5], 29) != BIT(b[4], 29) || BIT(d[5], 32) != BIT(b[4], 32))
		printf("d[5] broken\n");

	if (BIT(c[5], 26) != BIT(d[5], 26) || BIT(c[5], 27) != BIT(d[5], 27) || BIT(c[5], 29) != BIT(d[5], 29))
		printf("c[5] broken\n");

	if (BIT(b[5], 29) != BIT(c[5], 29) || BIT(b[5], 30) != 1 || BIT(b[5], 32) != 0)
		printf("b[5] broken\n");
    
	if (BIT(a[6], 29) != 1 || BIT(a[6], 30) != 0 || BIT(a[6], 32) != 1)
		printf("a[6] broken\n");

	if (BIT(d[6], 29) != BIT(b[5], 29))
		printf("d[6] broken\n");

	if (BIT(c[6], 29) != BIT(d[6], 29))
		printf("c[6] broken\n");
}

static void modify_message(uint8_t M1[BLOCK_SIZE])
{
	uint32_t *m = (uint32_t *)M1;
	uint32_t a[13], b[13], c[13], d[13];	/* chaining variables for each step. */

	md4_get_chaining_variables(M1, a, b, c, d);
	single_step_modification(m, a, b, c, d);
	md4_get_chaining_variables(M1, a, b, c, d);
	multi_step_modification(m, a, b, c, d);
//	check(m);
}

static void apply_collision_differential(const uint8_t M1[BLOCK_SIZE], uint8_t M2[BLOCK_SIZE])
{
	uint32_t *m = (uint32_t *)M2;

	memcpy(M2, M1, BLOCK_SIZE);
	m[1] += (1U << 31);
	m[2] += (1U << 31) - (1U << 28);
	m[12] -= (1U << 16);
}

int main()
{
	uint8_t M1[BLOCK_SIZE], M2[BLOCK_SIZE];
	uint8_t hash1[HASH_LENGTH], hash2[HASH_LENGTH];
	int found_collision;
	size_t i;

	srand(time(NULL));
	found_collision = 0;

	while (!found_collision) {
		for (i = 0; i < BLOCK_SIZE; i++)
			M1[i] = rand() & 0xff;

		modify_message(M1);
		apply_collision_differential(M1, M2);
		md4_hash(M1, 8 * BLOCK_SIZE, hash1);
		md4_hash(M2, 8 * BLOCK_SIZE, hash2);

		if (memcmp(hash1, hash2, HASH_LENGTH) == 0)
			found_collision = 1;

		++attempts;
	}

	printf("Found MD4 collision!\n");
	printf("Total attempts: %d\n", attempts);
	printf("Hash: ");
	print_hexstr(hash1, HASH_LENGTH);
	printf("\n");
	printf("M1: ");
	print_hexstr(M1, BLOCK_SIZE);
	printf("\n");
	printf("M2: ");
	print_hexstr(M2, BLOCK_SIZE);
	printf("\n");

	return 0;
}
