#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "rc4.h"
#include "base64.h"

#define KEY_BITS	128

static void get_random_key(uint8_t *key, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		key[i] = rand() & 0xff;
}

uint8_t *encryption_oracle(size_t *cipherlen, const uint8_t *request, size_t reqlen)
{
	const char *secret = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F";
	uint8_t cookie[100];
	size_t cookie_len;
	uint8_t key[KEY_BITS / 8];
	static uint8_t plaintext[1000], ciphertext[1000];

	memset(plaintext, 0, sizeof plaintext);
	memset(ciphertext, 0, sizeof ciphertext);
	b64decode(cookie, &cookie_len, secret, strlen(secret));

	memcpy(plaintext, request, reqlen);
	memcpy(plaintext + reqlen, cookie, cookie_len);

	get_random_key(key, sizeof key);
	rc4_init(key, sizeof key);
	rc4_process(ciphertext, plaintext, reqlen + cookie_len);

	*cipherlen = reqlen + cookie_len;

	return ciphertext;
}

static size_t find_cookie_len()
{
	const uint8_t request[1] = {0x61};
	uint8_t *ciphertext;
	size_t cipherlen;

	ciphertext = encryption_oracle(&cipherlen, request, sizeof request);

	return cipherlen - sizeof request;
}

/* Use bias of z16 toward 0xf0 and bias of z32 toward 0xe0.
 * if (n <= 14)
 * 	number of A = 14 - n
 * 	byte = z16
 * else if (n <= 30)
 * 	number of A = 30 - n
 * 	byte = z32
 */
static uint8_t decrypt_byte(size_t n)
{
	size_t counts[256] = {0};
	uint8_t request[100];
	uint8_t plaintext_byte;
	uint8_t *ciphertext;
	size_t cipherlen;

	size_t bias_index;
	uint8_t bias_byte;
	size_t num_A;

	size_t i;
	size_t max_counts;

	if (n <= 14) {
		bias_index = 16;
		bias_byte = 0xf0;
		num_A = 14 - n;
	} else if (n <= 30) {
		bias_index = 32;
		bias_byte = 0xe0;
		num_A = 30 - n;
	} else {
		return 0x00;	/* Assume cookie is at most 30 bytes... */
	}

	request[0] = '/';
	memset(request + 1, 'A', num_A);

	/* This is really slow... I don't see how 2^32 trials would work in less than a day. */
	for (i = 0; i < (1U << 24); i++) {
		ciphertext = encryption_oracle(&cipherlen, request, 1 + num_A);
		counts[ciphertext[bias_index - 1]] += 1;
	}

	max_counts = 0;

	for (i = 0; i < 256; i++) {
		if (counts[(uint8_t)i ^ bias_byte] >= max_counts) {
			max_counts = counts[(uint8_t)i ^ bias_byte];
			plaintext_byte = (uint8_t)i;
		}
	}

	return plaintext_byte;
}

void decrypt_cookie(uint8_t *cookie, size_t *cookie_len)
{
	size_t i;

	*cookie_len = find_cookie_len();

	for (i = 0; i < *cookie_len; i++) {
		cookie[i] = decrypt_byte(i);
		printf("%c", cookie[i]);
		fflush(stdout);
	}

	printf("\n");
}

int main()
{
	uint8_t cookie[100];
	size_t cookie_len;

	srand(time(NULL));
	decrypt_cookie(cookie, &cookie_len);

	printf("Decrypted cookie: ");
	fwrite(cookie, cookie_len, 1, stdout);
	printf("\n");

	return 0;
}
