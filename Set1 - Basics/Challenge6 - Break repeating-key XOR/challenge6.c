#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <ctype.h>

#define MAX_KEYSIZE 40

static int to_index(char a)
{
	if (a >= 'A' && a <= 'Z')
		return a - 'A';

	if (a >= 'a' && a <= 'z')
		return a - 'a' + 26;

	if (a >= '0' && a <= '9')
		return a - '0' + 52;

	if (a == '+')
		return 62;

	if (a == '/')
		return 63;

	if (a == '=')
		return 0;

	return -1;
}

static int b64decode(uint8_t *bytes, size_t *blen, const char *b64str, size_t len)
{
	uint32_t temp;
	size_t i;

	if (len % 4)
		return -1;

	for (i = 0; i < len; i++) {
		if (!((b64str[i] >= 'A' && b64str[i] <= 'Z') || (b64str[i] >= 'a' && b64str[i] <= 'z') || (b64str[i] >= '0' && b64str[i] <= '9')
			|| (b64str[i] == '+') || (b64str[i] == '/') || (b64str[i] == '=')))
			return -1;

		if (b64str[i] == '=') {
			if (i < len - 2)
				return -1;

			if (b64str[len - 1] != '=')
				return -1;
		}
	}

	for (i = 0; i < len / 4 - 1; i++) {
		temp = (to_index(b64str[4 * i]) << 18) | (to_index(b64str[4 * i + 1]) << 12) | (to_index(b64str[4 * i + 2]) << 6) | to_index(b64str[4 * i + 3]);
		bytes[3 * i] = temp >> 16;
		bytes[3 * i + 1] = (temp >> 8) & 0xff;
		bytes[3 * i + 2] = temp & 0xff;
	}

	temp = (to_index(b64str[4 * i]) << 18) | (to_index(b64str[4 * i + 1]) << 12) | (to_index(b64str[4 * i + 2]) << 6) | to_index(b64str[4 * i + 3]);
	bytes[3 * i] = temp >> 16;
	*blen = 3 * i + 1;

	if (b64str[len - 2] != '=') {
		bytes[3 * i + 1] = (temp >> 8) & 0xff;
		*blen = 3 * i + 2;
	}

	if (b64str[len - 1] != '=') {
		bytes[3 * i + 2] = temp & 0xff;
		*blen = 3 * i + 3;
	}

	return 0;
}

static void xor_decrypt(uint8_t *plain, const uint8_t *cipher, size_t clen, const uint8_t *key, size_t klen)
{
	size_t i;

	for (i = 0; i < clen; i++)
		plain[i] = cipher[i] ^ key[i % klen];
}

static int ispunctuation(uint8_t c)
{
	switch (c) {
		case '\'':
		case '\"':
		case '.':
		case ',':
		case '!':
		case '?':
		case '(':
		case ')':
		case ';':
		case ':':
		case '-':
			return 1;
		default:
			return 0;
	}

}

static int is_printable(const uint8_t *str, size_t len, uint8_t key, size_t keysize, size_t index)
{
	size_t i;

	for (i = index; i < len; i += keysize) {
		if (!(isalnum(str[i] ^ key) || isspace(str[i] ^ key) || ispunctuation(str[i] ^ key)))
			return 0;
	}

	return 1;
}

static double frequency_test(const uint8_t *str, size_t len, size_t index, uint8_t key, size_t keylen)
{
	const double expected_freqs[26] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};
	double distance = 0.0;
	double freqs[26];
	size_t N;
	size_t i;

	for (i = 0; i < 26; i++)
		freqs[i] = 0.0;

	N = 0;

	for (i = index; i < len; i += keylen) {
		if (isalpha(str[i])) {
			++freqs[tolower(str[i]) - 'a'];
			++N;
		}
	}

	for (i = 0; i < 26; i++)
		distance += fabs(freqs[i] * 100.0 / N - expected_freqs[i]);

	return distance;
}

static uint8_t get_single_xor_key(size_t index, size_t keysize, const uint8_t *cipher, size_t len)
{
	double score, best_score = 99999.99;
	uint32_t k, best_k;

	for (k = 0; k < 256; k++) {
		if (is_printable(cipher, len, (uint8_t)k, keysize, index)) {
			score = frequency_test(cipher, len, index, (uint8_t)k, keysize);

			if (score < best_score) {
				best_score = score;
				best_k = k;
			}
		}
	}

	return best_k;
}

void get_key(uint8_t *key, size_t KEYSIZE, const uint8_t *cipher, size_t len)
{
	size_t i;

	for (i = 0; i < KEYSIZE; i++)
		key[i] = get_single_xor_key(i, KEYSIZE, cipher, len);
}

int main()
{
	uint8_t plain[10000];
	uint8_t key[MAX_KEYSIZE + 1];

	FILE *filePtr;
	char b64str[10000];
	uint8_t cipher[10000];
	size_t clen;
	char *p;
	size_t siz;
	size_t klen, j;
	int good;

	filePtr = fopen("6.txt", "r");

	if (!filePtr) {
		perror("fopen");
		return -1;
	}

	p = b64str;
	siz = sizeof b64str;

	while (fgets(p, siz, filePtr) != NULL) {
		if (p[strlen(p) - 1] == '\n')
			p[strlen(p) - 1] = '\0';

		siz -= strlen(p);
		p += strlen(p);
	}

	if (b64decode(cipher, &clen, b64str, strlen(b64str)) != 0) {
		printf("Invalid Base64 string.\n");
		fclose(filePtr);
		return -1;
	}

	for (klen = 2; klen <= MAX_KEYSIZE; klen++) {
		get_key(key, klen, cipher, clen);
		xor_decrypt(plain, cipher, clen, key, klen);

		key[klen] = '\0';
		plain[clen] = '\0';

		if (is_printable(plain, clen, 0, 1, 0)) {
			printf("KEY:\n%s\n\n", key);
			printf("PLAINTEXT:\n%s\n", plain);
		}
	}

	fclose(filePtr);
	return 0;
}
