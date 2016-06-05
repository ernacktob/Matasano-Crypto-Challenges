#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void xor_encrypt(char *cipher, const char *plain, size_t plen, const char *key, size_t klen)
{
	const char *index_table = "0123456789abcdef";
	uint8_t byte;
	size_t i;

	for (i = 0; i < plen; i++) {
		byte = plain[i] ^ key[i % klen];
		cipher[2 * i] = index_table[byte >> 4];
		cipher[2 * i + 1] = index_table[byte & 0xf];
	}

	cipher[2 * plen] = '\0';
}

int main(int argc, char **argv)
{
	const char *plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	const char *key = "ICE";
	char cipher[1000];

	xor_encrypt(cipher, plain, strlen(plain), key, strlen(key));
	printf("%s\n", cipher);

	return 0;
}
