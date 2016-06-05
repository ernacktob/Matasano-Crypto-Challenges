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

int hextob64(char *b64str, const char *hexstr, size_t len)
{
	const char *index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t temp;
	size_t i;

	if (len % 2)
		return -1;

	for (i = 0; i < len; i++) {
		if (!(((hexstr[i] >= '0') && (hexstr[i] <= '9')) || ((hexstr[i] >= 'a') && (hexstr[i] <= 'f'))))
			return -1;
	}

	i = 0;

	if (len >= 6) {
		for (i = 0; i < len; i += 6) {
			temp = (to_byte(hexstr[i], hexstr[i + 1]) << 16) | (to_byte(hexstr[i + 2], hexstr[i + 3]) << 8) | to_byte(hexstr[i + 4], hexstr[i + 5]);
			b64str[4 * (i / 6)] = index_table[temp >> 18];
			b64str[4 * (i / 6) + 1] = index_table[(temp >> 12) & 0x3f];
			b64str[4 * (i / 6) + 2] = index_table[(temp >> 6) & 0x3f];
			b64str[4 * (i / 6) + 3] = index_table[temp & 0x3f];
		}
	}

	if (i > len)
		i -= 6;

	if (i != len) {
		if (len % 6 == 2) {
			temp = to_byte(hexstr[i], hexstr[i + 1]) << 8;
			b64str[4 * (i / 6)] = index_table[temp >> 10];
			b64str[4 * (i / 6) + 1] = index_table[(temp >> 4) & 0x3f];
			b64str[4 * (i / 6) + 2] = '=';
			b64str[4 * (i / 6) + 3] = '=';
		} else {
			temp = (to_byte(hexstr[i], hexstr[i + 1]) << 16) | (to_byte(hexstr[i + 2], hexstr[i + 3]) << 8);
			b64str[4 * (i / 6)] = index_table[temp >> 18];
			b64str[4 * (i / 6) + 1] = index_table[(temp >> 12) & 0x3f];
			b64str[4 * (i / 6) + 2] = index_table[(temp >> 6) & 0x3f];
			b64str[4 * (i / 6) + 3] = '=';
		}

		i += 6;
	}

	b64str[4 * (i / 6)] = '\0';
	return 0;
}

int main()
{
	const char *hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	char b64string[100];

	if (hextob64(b64string, hexstring, strlen(hexstring)) != 0) {
		printf("Invalid hex string.\n");
		return -1;
	}

	printf("%s\n", b64string);

	return 0;
}
