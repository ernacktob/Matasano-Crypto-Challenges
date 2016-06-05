#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

/* Need to link with libcrypto */

#define BLOCK_SIZE 16

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

int main()
{
	const char *password = "YELLOW SUBMARINE";
	uint8_t plain[10000];
	AES_KEY AESkey;

	FILE *filePtr;
	char b64str[10000];
	uint8_t cipher[10000];
	size_t clen;
	uint8_t *t, *c, *p;
	size_t siz;

	filePtr = fopen("7.txt", "r");

	if (!filePtr) {
		perror("fopen");
		return -1;
	}

	t = b64str;
	siz = sizeof b64str;

	while (fgets(t, siz, filePtr) != NULL) {
		if (t[strlen(t) - 1] == '\n')
			t[strlen(t) - 1] = '\0';

		siz -= strlen(t);
		t += strlen(t);
	}

	if (b64decode(cipher, &clen, b64str, strlen(b64str)) != 0) {
		printf("Invalid Base64 string.\n");
		fclose(filePtr);
		return -1;
	}

	AES_set_decrypt_key(password, 128, &AESkey);

	for (c = cipher, p = plain; c < cipher + clen; c += BLOCK_SIZE, p += BLOCK_SIZE)
		AES_ecb_encrypt(c, p, &AESkey, AES_DECRYPT);

	plain[clen] = '\0';
	printf("%s\n", plain);

	fclose(filePtr);
	return 0;
}
