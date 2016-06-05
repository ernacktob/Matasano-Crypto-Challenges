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

int xor_hex_buffers(char *result, const char *a, const char *b, size_t len)
{
	const char *index_table = "0123456789abcdef";
	uint8_t byte;
	size_t i;

	if (len % 2)
		return -1;

	for (i = 0; i < len; i += 2) {
		byte = to_byte(a[i], a[i + 1]) ^ to_byte(b[i], b[i + 1]);
		result[i] = index_table[byte >> 4];
		result[i + 1] = index_table[byte & 0xf];
	}

	result[len] = '\0';

	return 0;
}

int main()
{
	const char *a = "1c0111001f010100061a024b53535009181c";
	const char *b = "686974207468652062756c6c277320657965";
	char xored[100];

	if (xor_hex_buffers(xored, a, b, strlen(a)) != 0) {
		printf("Invalid hex string.\n");
		return -1;
	}

	printf("%s\n", xored);

	return 0;
}
