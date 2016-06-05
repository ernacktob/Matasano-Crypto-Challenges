#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/aes.h>

static uint8_t random_bytes[AES_BLOCK_SIZE];

static void gen_random_key()
{
	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		random_bytes[i] = rand() % 256;
}

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

static void aes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, const uint8_t *iv)
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

static void aes_cbc_decrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, const uint8_t *iv)
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

uint8_t *encrypt_string(size_t *clen, const uint8_t *string, size_t len, const uint8_t *iv)
{
	const uint8_t *prefix = "comment1=cooking%20MCs;userdata=";
	const uint8_t *suffix = ";comment2=\%20like\%20a\%20pound\%20of\%20bacon";
	uint8_t *cipher;
	uint8_t *modified_string;
	size_t plen;
	size_t i;
	AES_KEY key;

	plen = strlen(prefix) + len + strlen(suffix);
	modified_string = malloc(plen + AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE);

	if (modified_string == NULL)
		return NULL;

	cipher = malloc(plen + AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE);

	if (cipher == NULL) {
		free(modified_string);
		return NULL;
	}

	memcpy(modified_string, prefix, strlen(prefix));
	memcpy(modified_string + strlen(prefix), string, len);
	memcpy(modified_string + strlen(prefix) + len, suffix, strlen(suffix));

	for (i = strlen(prefix); i < strlen(prefix) + len; i++) {
		if (modified_string[i] == ';' || modified_string[i] == '=')
			modified_string[i] = ' ';
	}

	PKCS7_Padding(modified_string, plen, AES_BLOCK_SIZE);

	AES_set_encrypt_key(random_bytes, 128, &key);
	aes_cbc_encrypt(modified_string, cipher, plen + AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE, &key, iv);

	free(modified_string);
	*clen = plen + AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE;
	return cipher;
}

int test_admin(const uint8_t *cipher, size_t clen, const uint8_t *iv)
{
	const uint8_t *admin_string = ";admin=true;";
	uint8_t *plain;
	size_t plen;
	AES_KEY key;

	plain = malloc(clen);

	if (plain == NULL)
		return -1;

	AES_set_decrypt_key(random_bytes, 128, &key);
	aes_cbc_decrypt(cipher, plain, clen, &key, iv);
	plen = clen - plain[clen - 1];

	if (memmem(plain, plen, admin_string, strlen(admin_string)) != NULL) {
		free(plain);
		return 1;
	}

	free(plain);
	return 0;
}

int main()
{
	const uint8_t *input_string = "{admin}true";
	uint8_t *encrypted_string;
	size_t clen;
	size_t i;

	uint8_t iv[AES_BLOCK_SIZE];

	srand(time(NULL));
	gen_random_key();

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		iv[i] = rand() % 256;

	encrypted_string = encrypt_string(&clen, input_string, strlen(input_string), iv);

	if (encrypted_string == NULL) {
		perror("malloc");
		return -1;
	}

	encrypted_string[16] ^= 0x40;	/* { --> ; */
	encrypted_string[22] ^= 0x40;	/* } --> = */

	if (test_admin(encrypted_string, clen, iv) == 1) {
		printf("Congratulations, you are admin.\n");
		free(encrypted_string);
		return 0;
	}

	printf("Not admin.\n");
	free(encrypted_string);
	return 0;
}
