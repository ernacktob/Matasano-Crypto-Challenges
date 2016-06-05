#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

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

static void xor_blocks(uint8_t *b, const uint8_t *a, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		b[i] ^= a[i];
}

void PKCS7_Padding(uint8_t *data, size_t len, size_t blocklen)
{
	size_t i;

	for (i = len; i < len + (blocklen - len % blocklen); i++)
		data[i] = blocklen - len % blocklen;
}

void aes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, uint8_t *iv)
{
	uint8_t cipher_block[AES_BLOCK_SIZE];
	size_t block;

	memcpy(cipher_block, iv, AES_BLOCK_SIZE);

	for (block = 0; block < len / AES_BLOCK_SIZE; block++) {
		xor_blocks(cipher_block, in + block * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		AES_ecb_encrypt(cipher_block, out + block * AES_BLOCK_SIZE, key, AES_ENCRYPT);
		memcpy(cipher_block, out + block * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	}
}

void aes_cbc_decrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, const uint8_t *iv)
{
	uint8_t cipher_block[AES_BLOCK_SIZE];
	size_t block;

	for (block = len / AES_BLOCK_SIZE - 1; block > 0; block--) {
		AES_ecb_encrypt(in + block * AES_BLOCK_SIZE, out + block * AES_BLOCK_SIZE, key, AES_DECRYPT);
		memcpy(cipher_block, in + (block - 1) * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		xor_blocks(out + block * AES_BLOCK_SIZE, cipher_block, AES_BLOCK_SIZE);
	}

	AES_ecb_encrypt(in, out, key, AES_DECRYPT);
	memcpy(cipher_block, iv, AES_BLOCK_SIZE);
	xor_blocks(out, cipher_block, AES_BLOCK_SIZE);
}

int main()
{
	const char *password = "YELLOW SUBMARINE";
	const uint8_t iv[AES_BLOCK_SIZE] = {'\x00'};
	uint8_t plain[10000];
	AES_KEY AESkey;

	FILE *filePtr;
	char b64str[10000];
	uint8_t cipher[10000];
	size_t clen;
	uint8_t *t, *c, *p;
	size_t siz;

	filePtr = fopen("10.txt", "r");

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
	aes_cbc_decrypt(cipher, plain, clen, &AESkey, iv);

	fwrite(plain, clen - plain[clen - 1], 1, stdout);

	AES_set_encrypt_key(password, 128, &AESkey);
	aes_cbc_encrypt(plain, cipher, clen, &AESkey, "\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
	AES_set_decrypt_key(password, 128, &AESkey);
	aes_cbc_decrypt(cipher, plain, clen, &AESkey, "\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

	fwrite(plain, clen - plain[clen - 1], 1, stdout);

	fclose(filePtr);
	return 0;
}
