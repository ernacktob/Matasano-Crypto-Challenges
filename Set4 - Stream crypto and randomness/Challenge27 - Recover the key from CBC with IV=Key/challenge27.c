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

uint8_t *get_ciphertext(size_t *clen)
{
	const char *message = "comment1=cooking%20MCs;comment2=ilovekfc;qq=send";
	uint8_t *cipher;
	size_t plen;
	AES_KEY key;

	plen = strlen(message);
	cipher = malloc(plen);

	if (cipher == NULL)
		return NULL;

	AES_set_encrypt_key(random_bytes, 128, &key);
	aes_cbc_encrypt(message, cipher, plen, &key, random_bytes); /* Use key as IV */

	*clen = plen;
	return cipher;
}

uint8_t *process_ciphertext(size_t *errlen, const uint8_t *cipher, size_t len)
{
	const uint8_t *no_error_msg = "Operation successful.";
	const uint8_t *error_msg = "The message is not ASCII compliant: ";
	uint8_t *error_string;
	uint8_t *plaintext;
	size_t i;
	int not_ascii;
	AES_KEY key;

	plaintext = malloc(len);

	if (plaintext == NULL)
		return NULL;

	error_string = malloc(len + 100);

	if (error_string == NULL) {
		free(plaintext);
		return NULL;
	}

	AES_set_decrypt_key(random_bytes, 128, &key);
	aes_cbc_decrypt(cipher, plaintext, len, &key, random_bytes);

	not_ascii = 0;

	for (i = 0; i < len; i++) {
		if (plaintext[i] >= 0x80) {
			not_ascii = 1;
			break;
		}
	}

	if (not_ascii) {
		memcpy(error_string, error_msg, strlen(error_msg));
		memcpy(error_string + strlen(error_msg), plaintext, len);
		*errlen = strlen(error_msg) + len;
	} else {
		memcpy(error_string, no_error_msg, strlen(no_error_msg));
		*errlen = strlen(no_error_msg);
	}

	free(plaintext);
	return error_string;
}

int main()
{
	uint8_t key[AES_BLOCK_SIZE];
	uint8_t *new_plaintext;
	uint8_t *error_string;
	uint8_t *encrypted_string;
	size_t clen, errlen;
	size_t i;

	srand(time(NULL));
	gen_random_key();

	encrypted_string = get_ciphertext(&clen);

	if (encrypted_string == NULL) {
		perror("malloc");
		return -1;
	}

	if (clen < 3 * AES_BLOCK_SIZE) {
		printf("String is not long enough.\n");
		free(encrypted_string);
		return 0;
	}

	memset(encrypted_string + AES_BLOCK_SIZE, 0, AES_BLOCK_SIZE);
	memcpy(encrypted_string + 2 * AES_BLOCK_SIZE, encrypted_string, AES_BLOCK_SIZE);

	error_string = process_ciphertext(&errlen, encrypted_string, clen);
	free(encrypted_string);

	if (error_string == NULL) {
		perror("malloc");
		return -1;
	}

	if (strncmp(error_string, "Operation successful.", errlen) == 0) {
		printf("The string was ASCII compliant.\n");
		free(error_string);
		return 0;
	} else if (errlen < strlen("The message is not ASCII compliant: ") + 3 * AES_BLOCK_SIZE) {
		printf("Something wrong happened.\n");
		free(error_string);
		return 0;
	} else if (strncmp(error_string, "The message is not ASCII compliant: ", strlen("The message is not ASCII compliant: ")) != 0) {
		printf("Something else wrong happened.\n");
		free(error_string);
		return 0;
	}

	new_plaintext = error_string + strlen("The message is not ASCII compliant: ");
	memcpy(key, new_plaintext, AES_BLOCK_SIZE);
	xor_blocks(key, new_plaintext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

	if (memcmp(key, random_bytes, AES_BLOCK_SIZE) != 0)
		printf("Error while recovering the key.\n");
	else
		printf("The key was successfully recovered.\n");

	free(error_string);
	return 0;
}
