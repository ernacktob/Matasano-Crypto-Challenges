#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

static void xor_blocks(uint8_t *b, const uint8_t *a, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		b[i] ^= a[i];
}

static void PKCS7_Padding(uint8_t *data, size_t len, size_t blocklen)
{
	size_t i;

	for (i = len; i < len + (blocklen - len % blocklen); i++)
		data[i] = blocklen - len % blocklen;
}

static int PKCS7_Valid_Padding(const uint8_t *data, size_t len, size_t blocklen)
{
	uint8_t pad;
	size_t i;

	pad = data[len - 1];

	if (len % blocklen || pad == 0 || pad > blocklen || pad >= len)
		return 0;

	for (i = len - 1; i >= len - pad; i--) {
		if (data[i] != pad)
			return 0;
	}

	return 1;
}

void cbc_mac(uint8_t mac[AES_BLOCK_SIZE], const uint8_t *in, size_t len, const AES_KEY *key, const uint8_t *iv)
{
	uint8_t cipher_block1[AES_BLOCK_SIZE];
	uint8_t cipher_block2[AES_BLOCK_SIZE];
	size_t block;

	memcpy(cipher_block1, iv, AES_BLOCK_SIZE);

	for (block = 0; block < len / AES_BLOCK_SIZE; block++) {
		xor_blocks(cipher_block1, in + block * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		AES_ecb_encrypt(cipher_block1, cipher_block2, key, AES_ENCRYPT);
		memcpy(cipher_block1, cipher_block2, AES_BLOCK_SIZE);
	}

	memcpy(mac, cipher_block1, AES_BLOCK_SIZE);
}

uint8_t *get_padded_string(size_t *padlen, const uint8_t *string, size_t len)
{
	uint8_t *padded_string;

	padded_string = malloc(len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE);

	if (padded_string == NULL)
		return NULL;

	memcpy(padded_string, string, len);
	PKCS7_Padding(padded_string, len, AES_BLOCK_SIZE);

	*padlen = len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE;
	return padded_string;
}

uint8_t *get_unpadded_string(size_t *unpadlen, const uint8_t *padded_string, size_t len)
{
	uint8_t *string;
	uint8_t pad;
	size_t i;

	if (len % AES_BLOCK_SIZE != 0)
		return NULL;

	pad = padded_string[len - 1];

	if (pad > AES_BLOCK_SIZE || pad >= len)
		return NULL;

	for (i = len - 1; i >= len - pad; i--) {
		if (padded_string[i] != pad)
			return NULL;
	}

	string = malloc(len - pad);

	if (string == NULL)
		return NULL;

	memcpy(string, padded_string, len - pad);
	*unpadlen = len - pad;

	return string;
}
