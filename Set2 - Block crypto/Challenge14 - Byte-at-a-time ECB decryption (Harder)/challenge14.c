#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/aes.h>

#define MAX_BLOCK_SIZE 100
#define MAX_PREFIX_LEN 30

typedef uint8_t *(encrypt_black_box_func)(const uint8_t *plain, size_t len, size_t *clen);

static AES_KEY key;

static uint8_t prefix[MAX_PREFIX_LEN];
static size_t prefixlen;

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

static void aes_ecb_encrypt(uint8_t *cipher, const uint8_t *plain, size_t len, const AES_KEY *key)
{
	const uint8_t *p;
	uint8_t *c;

	for (c = cipher, p = plain; c < cipher + len; c += AES_BLOCK_SIZE, p += AES_BLOCK_SIZE)
		AES_ecb_encrypt(p, c, key, AES_ENCRYPT);
}

static void PKCS7_Padding(uint8_t *data, size_t len, size_t blocklen)
{
	size_t i;

	for (i = len; i < len + (blocklen - len % blocklen); i++)
		data[i] = blocklen - len % blocklen;
}

static void gen_random_key()
{
	uint8_t random_bytes[AES_BLOCK_SIZE];
	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		random_bytes[i] = rand() % 256;

	AES_set_encrypt_key(random_bytes, 128, &key);
}

static void gen_random_prefix()
{
	size_t i;

	prefixlen = rand() % MAX_PREFIX_LEN;

	for (i = 0; i < prefixlen; i++)
		prefix[i] = rand() % 256;
}
static int detect_aes_ecb(const uint8_t *bytes, size_t len)
{
	size_t i, j;

	for (i = 0; i < len / AES_BLOCK_SIZE; i++) {
		for (j = i + 1; j < len / AES_BLOCK_SIZE; j++) {
			if (memcmp(bytes + i * AES_BLOCK_SIZE, bytes + j * AES_BLOCK_SIZE, AES_BLOCK_SIZE) == 0)
				return 1;
		}
	}

	return 0;
}

uint8_t *encrypt_blackbox(const uint8_t *plain, size_t len, size_t *clen)
{
	const char *b64str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	uint8_t append_bytes[1000];
	size_t appendlen;

	uint8_t *cipher;
	uint8_t *modified_plain;
	size_t plen;
	size_t i;

	b64decode(append_bytes, &appendlen, b64str, strlen(b64str));

	plen = prefixlen + len + appendlen;
	modified_plain = malloc(plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE));

	if (modified_plain == NULL)
		return NULL;

	cipher = malloc(plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE));

	if (cipher == NULL) {
		free(modified_plain);
		return NULL;
	}

	memcpy(modified_plain, prefix, prefixlen);
	memcpy(modified_plain + prefixlen, plain, len);
	memcpy(modified_plain + prefixlen + len, append_bytes, appendlen);
	PKCS7_Padding(modified_plain, plen, AES_BLOCK_SIZE);

	aes_ecb_encrypt(cipher, modified_plain, plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE), &key);
	*clen = plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE);

	free(modified_plain);
	return cipher;
}

size_t detect_block_size(encrypt_black_box_func encrypt)
{
	uint8_t plaintext[MAX_BLOCK_SIZE];
	uint8_t *cipher;
	size_t clen, prev_clen;
	size_t n;

	memset(plaintext, 'A', sizeof plaintext);
	cipher = encrypt(plaintext, 0, &clen);

	if (cipher == NULL)
		return 0;

	prev_clen = clen;
	free(cipher);

	for (n = 1; n < sizeof plaintext; n++) {
		cipher = encrypt(plaintext, n, &clen);

		if (cipher == NULL)
			return 0;

		free(cipher);

		if (clen != prev_clen)
			return clen - prev_clen;
	}

	return 0;
}

int detect_ecb_mode(encrypt_black_box_func encrypt)
{
	uint8_t plaintext[3 * MAX_BLOCK_SIZE];
	uint8_t *cipher;
	size_t clen;
	size_t block_size;

	block_size = detect_block_size(encrypt);

	if (block_size == 0)
		return -1;

	/* Need 3 blocks since the random prefix makes it that we might start in middle of a block. */
	memset(plaintext, 'A', 3 * block_size);
	cipher = encrypt(plaintext, 3 * block_size, &clen);

	if (cipher == NULL)
		return -1;

	if (detect_aes_ecb(cipher, clen)) {
		free(cipher);
		return 1;
	}

	free(cipher);
	return 0;
}

static size_t detect_first_full_user_block(encrypt_black_box_func encrypt, size_t block_size)
{
	uint8_t test_block[MAX_BLOCK_SIZE];
	uint8_t *cipher, *ori_cipher;
	size_t len;
	size_t block;

	ori_cipher = encrypt("", 0, &len);

	memset(test_block, 'A', block_size);
	cipher = encrypt(test_block, block_size, &len);

	block = 0;

	/* The first block that differs could contain part of the prefix.
	 * The next block is sure to be fully user-provided data block. */
	while (memcmp(cipher + block * block_size, ori_cipher + block * block_size, block_size) == 0)
		++block;

	free(ori_cipher);
	free(cipher);

	return block + 1;
}

static size_t detect_first_user_index(encrypt_black_box_func encrypt, size_t block_size, size_t start_block)
{
	uint8_t test_block[2 * MAX_BLOCK_SIZE];
	uint8_t a_block[MAX_BLOCK_SIZE];
	uint8_t *cipher;
	size_t len;
	size_t block, i;
	size_t startA, startB;

	/* Get block corresponding to all 'A' */
	memset(test_block, 'A', sizeof test_block);
	cipher = encrypt(test_block, 2 * block_size, &len);
	memcpy(a_block, cipher + start_block * block_size, block_size);
	free(cipher);

	/* Don't start from i = block_size, since it is useless. */
	for (i = block_size + 1; i < 2 * block_size; i++) {
		cipher = encrypt(test_block, i, &len);

		if (memcmp(cipher + start_block * block_size, a_block, block_size) == 0) {
			free(cipher);
			break;
		}

		free(cipher);
	}

	startA = 2 * block_size - i;

	/* If the first byte of the unknown string happens to be 'A', then the full a_block might
	 * have contained bytes from the unknown string and thus give higher start index than it really is.
	 * So repeat with 'B' block instead, and pick the lowest start index. */
	/* Get block corresponding to all 'B' */
	memset(test_block, 'B', sizeof test_block);
	cipher = encrypt(test_block, 2 * block_size, &len);
	memcpy(a_block, cipher + start_block * block_size, block_size);
	free(cipher);

	for (i = block_size + 1; i < 2 * block_size; i++) {
		cipher = encrypt(test_block, i, &len);

		if (memcmp(cipher + start_block * block_size, a_block, block_size) == 0) {
			free(cipher);
			break;
		}

		free(cipher);
	}

	startB = 2 * block_size - i;

	return startA < startB ? startA: startB;
}

static int detect_unknown_byte(uint8_t *ubyte, encrypt_black_box_func encrypt, const uint8_t *known_prefix,
				size_t block_size, size_t start_block, size_t start_index, size_t block, size_t index)
{
	uint8_t test_block[2 * MAX_BLOCK_SIZE];
	uint8_t *cipher, *ori_cipher;
	size_t len;
	int byte;

	/* Fill up first prefix block, and do the thing in the next block (start_block will be that) */
	if (block == 0) {
		memset(test_block, 'A', block_size - start_index + block_size - index - 1);
		memcpy(test_block + block_size - start_index + block_size - index - 1, known_prefix, index);
	} else {
		memset(test_block, 'A', block_size - start_index);
		memcpy(test_block + block_size - start_index, known_prefix + (block - 1) * block_size + index + 1, block_size - 1);
	}

	/* Kinda confusing, have to follow with a concrete example to get it.
	 * The first time test_block is used we don't really care about what's in it, just the length.
	 * Trust me, it works... */
	ori_cipher = encrypt(test_block, block_size - start_index + block_size - index - 1, &len);

	if (ori_cipher == NULL)
		return -1;

	for (byte = 0; byte < 256; byte++) {
		test_block[block_size - start_index + block_size - 1] = byte;
		cipher = encrypt(test_block, block_size - start_index + block_size, &len);

		if (cipher == NULL) {
			free(ori_cipher);
			return -1;
		}

		if (memcmp(cipher + start_block * block_size, ori_cipher + (start_block + block) * block_size, block_size) == 0) {
			free(cipher);
			break;
		}

		free(cipher);
	}

	free(ori_cipher);
	*ubyte = (uint8_t)byte;
	return 0;
}

uint8_t *detect_unknown_string(encrypt_black_box_func encrypt, size_t *len)
{
	uint8_t *unknown_string, *tmp;
	size_t unknown_len;
	size_t block_size;

	uint8_t *original_cipher;
	size_t original_len;
	uint8_t *temp_cipher;
	size_t temp_len = 0;

	size_t start_block, start_index;
	size_t block, i;

	original_cipher = encrypt("", 0, &original_len);

	if (original_cipher == NULL)
		return NULL;

	block_size = detect_block_size(encrypt);
	start_block = detect_first_full_user_block(encrypt, block_size);
	start_index = detect_first_user_index(encrypt, block_size, start_block);

	unknown_string = malloc(2 * block_size);

	if (unknown_string == NULL) {
		free(original_cipher);
		return NULL;
	}

	if (original_len == 0) {
		*len = original_len;
		free(original_cipher);
		return unknown_string;
	}

	block = 0;
	i = 0;

	while (1) {
		if (detect_unknown_byte(&unknown_string[block * block_size + i], encrypt, unknown_string, block_size, start_block, start_index, block, i) != 0) {
			free(unknown_string);
			free(original_cipher);
			return NULL;
		}

		++i;

		if (i == block_size) {
			i = 0;
			++block;
			tmp = realloc(unknown_string, (block + 2) * block_size);

			if (tmp == NULL) {
				free(unknown_string);
				free(original_cipher);
				return NULL;
			}

			unknown_string = tmp;
		}

		/* We want to put the padding here so that the first blocks are exactly like the original. */
		unknown_len = block * block_size + i;

		size_t j;
		for (j = unknown_len; j < unknown_len + block_size - (unknown_len + start_index) % block_size; j++)
			unknown_string[j] = (uint8_t)(block_size - (unknown_len + start_index) % block_size);

		temp_cipher = encrypt(unknown_string, unknown_len + (block_size - (unknown_len + start_index) % block_size), &temp_len);

		if (memcmp(temp_cipher, original_cipher, original_len) == 0) {
			free(temp_cipher);
			break;
		}

		free(temp_cipher);
	}

	free(original_cipher);

	*len = unknown_len;
	return unknown_string;
}

int main()
{
	uint8_t *unknown_string;
	size_t len;

	srand(time(NULL));

	gen_random_key();
	gen_random_prefix();

	printf("BLOCK SIZE: %lu\n", detect_block_size(encrypt_blackbox));
	printf("ECB MODE: %s\n", detect_ecb_mode(encrypt_blackbox) ? "yes" : "no");

	unknown_string = detect_unknown_string(encrypt_blackbox, &len);

	printf("\nUNKNOWN STRING:\n");
	fwrite(unknown_string, len, 1, stdout);
	printf("\n");

	free(unknown_string);
	return 0;
}
