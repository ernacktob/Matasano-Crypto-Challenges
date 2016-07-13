#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/aes.h>

#include "utils.h"

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

static void xor_blocks(uint8_t *c, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		c[i] = a[i] ^ b[i];
}

uint8_t *forge_message(size_t *forged_len, const uint8_t *desired_msg, size_t desired_len, const uint8_t secret_key[AES_BLOCK_SIZE], const uint8_t hash[AES_BLOCK_SIZE])
{
	uint8_t *forged_msg;
	uint8_t last_block[AES_BLOCK_SIZE];
	uint8_t intermediate_hash[AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	AES_KEY key;

	memset(iv, 0, sizeof iv);

	if (desired_len % AES_BLOCK_SIZE != 0)
		return NULL;

	/* Find block that encrypts to the correct hash. */
	AES_set_decrypt_key(secret_key, 128, &key);
	AES_ecb_encrypt(hash, last_block, &key, AES_DECRYPT);

	forged_msg = malloc(desired_len + AES_BLOCK_SIZE);

	if (forged_msg == NULL)
		return NULL;

	memcpy(forged_msg, desired_msg, desired_len);

	/* Find last cipher block that gets xored with last block before final hash. */
	AES_set_encrypt_key(secret_key, 128, &key);
	cbc_mac(intermediate_hash, forged_msg, desired_len, &key, iv);

	/* Last block of forged message, when xored with last cipher block, encrypts to correct hash. */
	xor_blocks(forged_msg + desired_len, last_block, intermediate_hash, AES_BLOCK_SIZE);
	*forged_len = desired_len + AES_BLOCK_SIZE;

	return forged_msg;
}

int main()
{
	const char *secret_key = "YELLOW SUBMARINE";
	const char *desired_snippet = "alert('Ayo, the Wu is back!');//";
	const char *snippet = "alert('MZA who was that?');\n";
	const char *hashstr = "296b8d7cb78a243dda4d0a61d33bbdd1";
	char *padded_snippet, *forged_snippet;
	size_t padded_len, forged_len;
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t hash[AES_BLOCK_SIZE], computed_hash[AES_BLOCK_SIZE];
	AES_KEY key;
	int i;

	AES_set_encrypt_key(secret_key, 128, &key);
	memset(iv, 0, sizeof iv);

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		hash[i] = to_byte(hashstr[2 * i], hashstr[2 * i + 1]);

	padded_snippet = get_padded_string(&padded_len, snippet, strlen(snippet));
	cbc_mac(computed_hash, padded_snippet, padded_len, &key, iv);

	free(padded_snippet);

	/* Check that we get the correct hash for the given snippet. */
	if (memcmp(computed_hash, hash, AES_BLOCK_SIZE) != 0) {
		printf("Error: computed hash for snippet doesn't match!\n");
		return -1;
	}

	forged_snippet = forge_message(&forged_len, desired_snippet, strlen(desired_snippet), secret_key, hash);
	cbc_mac(computed_hash, forged_snippet, forged_len, &key, iv);

	/* Check that we get the correct hash for the forged snippet. */
	if (memcmp(computed_hash, hash, AES_BLOCK_SIZE) != 0) {
		printf("Error: computed hash for forged snippet doesn't match!\n");
		free(forged_snippet);
		return -1;
	}

	fwrite(forged_snippet, forged_len, 1, stdout);
	free(forged_snippet);
	return 0;
}
