#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>

static uint8_t to_byte(char a, char b)
{
	uint8_t res = 0;

	if (a >= '0' && a <= '9')
		res += a - '0';
	else
		res += a - 'a' + 10;

	res *= 16;

	if (b >= '0' && b <= '9')
		res += b - '0';
	else
		res += b - 'a' + 10;

	return res;
}

static void hex_to_bytes(uint8_t *bytes, const char *hexstr, size_t nbytes)
{
	size_t i;

	for (i = 0; i < nbytes; i++)
		bytes[i] = to_byte(hexstr[2 * i], hexstr[2 * i + 1]);
}

static void xor_bytes(uint8_t *res, uint8_t byte, const uint8_t *a, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		res[i] = a[i] ^ byte;
}

static double chi_test(const uint8_t *str, size_t len)
{
	const double expected_freqs[26] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};
	double freqs[26];
	double Xr, Xo;
	size_t N, M;
	size_t i;

	for (i = 0; i < 26; i++)
		freqs[i] = 0.0;

	N = 0;
	M = 0;

	for (i = 0; i < len; i++) {
		if (isalpha(str[i])) {
			++freqs[tolower(str[i]) - 'a'];
			++N;
			++M;
		}

		if (isspace(str[i]))
			++M;
	}

	if (M < len * 7 / 8)
		return 999999.9;

	Xr = (100.0 * N) / 26.0;
	Xo = 0.0;

	for (i = 0; i < 26; i++)
		Xo += freqs[i] * expected_freqs[i];

	return Xo / Xr;
}

void decrypt(const uint8_t *cipher, size_t len, uint8_t *plaintext, uint8_t *key, double *scre)
{
	const double expected_chi = 1.73;
	double score, best_score = 999999.99;
	uint32_t k, best_k;
	size_t i;

	for (k = 0; k < 256; k++) {
		xor_bytes(plaintext, (uint8_t)k, cipher, len);
		score = fabs(chi_test(plaintext, len) - expected_chi);

		if (score < best_score) {
			best_score = score;
			best_k = k;
		}
	}

	xor_bytes(plaintext, (uint8_t)best_k, cipher, len);
	plaintext[len] = '\0';
	*key = best_k;
	*scre = best_score;
}

int main()
{
	FILE *filePtr;
	uint8_t hexstr[100];
	uint8_t cipherbytes[100];
	uint8_t plaintext[100];
	uint8_t key;
	size_t line, best_line;
	double score, best_score = 99999.99;

	filePtr = fopen("4.txt", "r");

	if (!filePtr) {
		perror("fopen");
		return -1;
	}

	line = 0;

	while (fgets(hexstr, sizeof hexstr, filePtr) != NULL) {
		if (hexstr[strlen(hexstr) - 1] == '\n')
			hexstr[strlen(hexstr) - 1] = '\0';

		if (strlen(hexstr) % 2) {
			printf("%s\n", hexstr);
			printf("Invalid hex string.\n");
			fclose(filePtr);
			return -1;
		}

		hex_to_bytes(cipherbytes, hexstr, strlen(hexstr) / 2);
		decrypt(cipherbytes, strlen(hexstr) / 2, plaintext, &key, &score);

		if (score < best_score) {
			best_score = score;
			best_line = line;
		}

		++line;
	}

	line = 0;

	rewind(filePtr);

	while (fgets(hexstr, sizeof hexstr, filePtr) != NULL) {
		if (hexstr[strlen(hexstr) - 1] == '\n')
			hexstr[strlen(hexstr) - 1] = '\0';

		if (line == best_line)
			break;

		++line;
	}

	hex_to_bytes(cipherbytes, hexstr, strlen(hexstr) / 2);
	decrypt(cipherbytes, strlen(hexstr) / 2, plaintext, &key, &score);

	printf("Line: %lu\n", line);
	printf("Ciphertext: %s\n", hexstr);
	printf("Key: %c\n", key);
	printf("Message: %s\n", plaintext);

	fclose(filePtr);
	return 0;
}
