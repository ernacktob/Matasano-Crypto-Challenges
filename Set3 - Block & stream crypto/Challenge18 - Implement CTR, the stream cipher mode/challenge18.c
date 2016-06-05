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

void aes_ctr_encrypt_decrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, const uint8_t *nonce)
{
	uint8_t stream_block[AES_BLOCK_SIZE];
	uint64_t counter;

	memcpy(stream_block, nonce, AES_BLOCK_SIZE / 2);

	for (counter = 0; counter < len / AES_BLOCK_SIZE; counter++) {
		memcpy(stream_block + AES_BLOCK_SIZE / 2, &counter, AES_BLOCK_SIZE / 2);
		AES_ecb_encrypt(stream_block, out + counter * AES_BLOCK_SIZE, key, AES_ENCRYPT);
		xor_blocks(out + counter * AES_BLOCK_SIZE, in + counter * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	}

	if (len % AES_BLOCK_SIZE) {
		memcpy(stream_block + AES_BLOCK_SIZE / 2, &counter, AES_BLOCK_SIZE / 2);
		AES_ecb_encrypt(stream_block, out + counter * AES_BLOCK_SIZE, key, AES_ENCRYPT);
		xor_blocks(out + counter * AES_BLOCK_SIZE, in + counter * AES_BLOCK_SIZE, len % AES_BLOCK_SIZE);
	}
}

int main()
{
	const char *password = "YELLOW SUBMARINE";
	const uint8_t nonce[AES_BLOCK_SIZE / 2] = {'\x00'};
	uint8_t plain[10000];
	AES_KEY AESkey;

	const char *b64str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	uint8_t cipher[10000];
	size_t clen;

	if (b64decode(cipher, &clen, b64str, strlen(b64str)) != 0) {
		printf("Invalid Base64 string.\n");
		return -1;
	}

	AES_set_encrypt_key(password, 128, &AESkey);
	aes_ctr_encrypt_decrypt(cipher, plain, clen, &AESkey, nonce);

	fwrite(plain, clen, 1, stdout);
	printf("\n");
	return 0;
}
