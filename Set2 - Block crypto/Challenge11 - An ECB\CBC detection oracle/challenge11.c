#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/aes.h>

#define MAX_TRIALS 10000
static int used_ecb;

static void xor_blocks(uint8_t *b, const uint8_t *a, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		b[i] ^= a[i];
}

static void aes_ecb_encrypt(uint8_t *cipher, const uint8_t *plain, size_t len, const AES_KEY *key)
{
	uint8_t *c, *p;

	for (c = cipher, p = plain; c < cipher + len; c += AES_BLOCK_SIZE, p += AES_BLOCK_SIZE)
		AES_ecb_encrypt(p, c, key, AES_ENCRYPT);
}

static void aes_cbc_encrypt(uint8_t *cipher, const uint8_t *plain, size_t len, const AES_KEY *key, const uint8_t *iv)
{
	uint8_t cipher_block[AES_BLOCK_SIZE];
	size_t block;

	memcpy(cipher_block, iv, AES_BLOCK_SIZE);

	for (block = 0; block < len / AES_BLOCK_SIZE; block++) {
		xor_blocks(cipher_block, plain + block * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		AES_ecb_encrypt(cipher_block, cipher + block * AES_BLOCK_SIZE, key, AES_ENCRYPT);
		memcpy(cipher_block, cipher + block * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	}
}

void PKCS7_Padding(uint8_t *data, size_t len, size_t blocklen)
{
	size_t i;

	for (i = len; i < len + (blocklen - len % blocklen); i++)
		data[i] = blocklen - len % blocklen;
}

void gen_random_key(AES_KEY *key)
{
	uint8_t random_bytes[AES_BLOCK_SIZE];
	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		random_bytes[i] = rand() % 256;

	AES_set_encrypt_key(random_bytes, 128, key);
}

uint8_t *encrypt_blackbox(const uint8_t *plain, size_t len, size_t *clen)
{
	uint8_t *cipher;
	uint8_t *modified_plain;
	size_t before, after;
	size_t plen;
	size_t i;

	uint8_t iv[AES_BLOCK_SIZE];
	AES_KEY key;

	gen_random_key(&key);

	before = 5 + rand() % 6;
	after = 5 + rand() % 6;
	plen = before + len + after;

	modified_plain = malloc(plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE));

	if (modified_plain == NULL)
		return NULL;

	cipher = malloc(plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE));

	if (cipher == NULL) {
		free(modified_plain);
		return NULL;
	}

	for (i = 0; i < before; i++)
		modified_plain[i] = rand() % 256;

	memcpy(modified_plain + before, plain, len);

	for (i = before + len; i < before + len + after; i++)
		modified_plain[i] = rand() % 256;

	PKCS7_Padding(modified_plain, plen, AES_BLOCK_SIZE);

	if (rand() % 2) {
		used_ecb = 1;
		aes_ecb_encrypt(cipher, modified_plain, plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE), &key);
	} else {
		used_ecb = 0;

		for (i = 0; i < sizeof iv; i++)
			iv[i] = rand() % 256;

		aes_cbc_encrypt(cipher, modified_plain, plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE), &key, iv);
	}

	*clen = plen + (AES_BLOCK_SIZE - plen % AES_BLOCK_SIZE);
	return cipher;
}

int detect_aes_ecb(const uint8_t *bytes, size_t len)
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

int main()
{
	uint8_t plaintext[10000];
	uint8_t *ciphertext;
	size_t clen;
	int correct = 0;
	int n;

	FILE *filePtr;

	filePtr = fopen("text", "r");
	fread(plaintext, sizeof plaintext, 1, filePtr);
	fclose(filePtr);

	srand(time(NULL));

	for (n = 0; n < MAX_TRIALS; n++) {
		ciphertext = encrypt_blackbox(plaintext, strlen(plaintext), &clen);

		if (ciphertext == NULL) {
			perror("malloc");
			return -1;
		}

		if (detect_aes_ecb(ciphertext, clen) == used_ecb)
			++correct;
		else
			printf("%d\n", used_ecb);

		free(ciphertext);
	}

	printf("Correct: %d/%d\n", correct, MAX_TRIALS);
	return 0;
}
