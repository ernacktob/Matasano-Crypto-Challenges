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

static uint32_t to_big_endian32(uint32_t n)
{
	uint32_t b0, b1, b2, b3;

	b0 = (n & 0xff000000) >> 24;
	b1 = (n & 0x00ff0000) >> 8;
	b2 = (n & 0x0000ff00) << 8;
	b3 = (n & 0x000000ff) << 24;

	return b0 | b1 | b2 | b3;
}

static uint32_t left_rotate(uint32_t n, int amount)
{
	return (n << amount) | (n >> (32 - amount));
}

int sha1_hash(const unsigned char *message, uint64_t ml, uint32_t hh[5])
{
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	uint32_t k0 = 0x5A827999;
	uint32_t k1 = 0x6ED9EBA1;
	uint32_t k2 = 0x8F1BBCDC;
	uint32_t k3 = 0xCA62C1D6;

	unsigned char *msg;
	uint64_t rem = (512 - ((ml + 8) % 512) + 448) % 512;
	uint64_t total_len = ml + 8 + rem + 64;
	uint64_t chunk;
	uint32_t w[80];
	unsigned char *p;
	int i;

	uint32_t a, b, c, d, e;
	uint32_t f, k;
	uint32_t temp;

	msg = calloc(total_len / 8, 1);

	if (msg == NULL) {
		fprintf(stderr, "Calloc failed. Error: %s\n", strerror(errno));
		return -1;
	}

	memcpy(msg, message, ml / 8);
	msg[ml / 8] = 0x80;
	*((uint64_t *)(msg + (ml + 8 + rem) / 8)) = to_big_endian64(ml);

	for (chunk = 0; chunk < total_len / 512; chunk++) {
		p = msg + chunk * 64;
		
		for (i = 0; i < 16; i++)
			w[i] = to_big_endian32(*((uint32_t *)p + i));

		for (i = 16; i < 80; i++)
			w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
	
		for (i = 0; i < 80; i++) {
			if (i <= 19) {
				f = (b & c) | ((~b) & d);
				k = k0;
			} else if (i <= 39) {
				f = b ^ c ^ d;
				k = k1;
			} else if (i <= 59) {
				f = (b & c) | (b & d) | (c & d);
				k = k2;
			} else if (i <= 79) {
				f = b ^ c ^ d;
				k = k3;
			}

			temp = left_rotate(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = left_rotate(b, 30);
			b = a;
			a = temp;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	hh[0] = h4;
	hh[1] = h3;
	hh[2] = h2;
	hh[3] = h1;
	hh[4] = h0;

	free(msg);
	return 0;
}
