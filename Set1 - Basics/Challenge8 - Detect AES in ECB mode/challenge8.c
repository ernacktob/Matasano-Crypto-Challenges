#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

int hex_to_bytes(uint8_t *bytes, const char *hexstr, size_t len)
{
	size_t i;

	if (len % 2)
		return -1;

	for (i = 0; i < len; i++) {
		if (!(((hexstr[i] >= '0') && (hexstr[i] <= '9')) || ((hexstr[i] >= 'a') && (hexstr[i] <= 'f'))))
			return -1;
	}

	for (i = 0; i < len; i += 2)
		bytes[i / 2] = to_byte(hexstr[i], hexstr[i + 1]);

	return 0;
}

unsigned int detect_aes_ecb(const uint8_t *bytes, size_t len)
{
	unsigned int max_freq = 0;
	unsigned int freqs[256] = {0};
	size_t i;

	for (i = 0; i < len; i += 16)
		++freqs[bytes[i]];

	for (i = 0; i < 256; i++) {
		if (freqs[i] > max_freq)
			max_freq = freqs[i];
	}

	return max_freq;
}

int main()
{
	char hexstr[1000];
	uint8_t bytes[500];
	unsigned int score, best_score = 0;
	size_t line, best_line;

	FILE *filePtr;

	filePtr = fopen("8.txt", "r");

	if (!filePtr) {
		perror("fopen");
		return -1;
	}

	line = 1;

	while (fgets(hexstr, sizeof hexstr, filePtr) != NULL) {
		if (hexstr[strlen(hexstr) - 1] == '\n')
			hexstr[strlen(hexstr) - 1] = '\0';

		if (hex_to_bytes(bytes, hexstr, strlen(hexstr)) != 0) {
			printf("Invalid hex string.\n");
			fclose(filePtr);
			return 0;
		}

		score = detect_aes_ecb(bytes, strlen(hexstr) / 2);

		if (score > best_score) {
			best_score = score;
			best_line = line;
		}

		++line;
	}

	printf("Ciphertext encrypted with AES ECB: line %lu\n", best_line);

	fclose(filePtr);
	return 0;
}
