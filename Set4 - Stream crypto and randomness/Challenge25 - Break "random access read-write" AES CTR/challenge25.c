#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/aes.h>

static AES_KEY AESkey;

static void xor_blocks(uint8_t *b, const uint8_t *a, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		b[i] ^= a[i];
}

static void aes_ctr_encrypt_decrypt(const uint8_t *in, uint8_t *out, size_t len, const AES_KEY *key, const uint8_t *nonce)
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

void get_ciphertext(uint8_t *cipher, size_t *clen)
{
	const uint8_t nonce[AES_BLOCK_SIZE / 2] = {'\x00'};
	uint8_t password[AES_BLOCK_SIZE];
	uint8_t plain[10000];
	FILE *filePtr;
	size_t plen, i;

	filePtr = fopen("text.txt", "r");

	plen = fread(plain, 1, sizeof plain, filePtr);
	fclose(filePtr);

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		password[i] = rand() & 0xff;

	AES_set_encrypt_key(password, 128, &AESkey);
	aes_ctr_encrypt_decrypt(plain, cipher, plen, &AESkey, nonce);
	*clen = plen;
}

void edit(uint8_t *ciphertext, size_t len, size_t offset, uint8_t newtext)
{
	const uint8_t nonce[AES_BLOCK_SIZE / 2] = {'\x00'};
	uint8_t counter_block[AES_BLOCK_SIZE], stream_block[AES_BLOCK_SIZE];
	uint64_t counter;
	uint8_t stream_byte;
	uint8_t plaintext[10000];

	if (offset >= len)
		return;

	memcpy(counter_block, nonce, AES_BLOCK_SIZE / 2);

	for (counter = 0; counter <= offset / AES_BLOCK_SIZE; counter++) {
		memcpy(counter_block + AES_BLOCK_SIZE / 2, &counter, AES_BLOCK_SIZE / 2);
		AES_ecb_encrypt(counter_block, stream_block, &AESkey, AES_ENCRYPT);
	}

	stream_byte = stream_block[offset % AES_BLOCK_SIZE];
	ciphertext[offset] = newtext ^ stream_byte;
}

void crack_plaintext(uint8_t *plain, const uint8_t *cipher, size_t clen)
{
	uint8_t copy[10000];
	uint8_t p, new_p, c, new_c;
	size_t i;

	memcpy(copy, cipher, sizeof copy);

	for (i = 0; i < clen; i++) {
		c = cipher[i];
		new_p = 'A';
		edit(copy, clen, i, new_p);
		new_c = copy[i];
		p = new_p ^ (c ^ new_c);
		plain[i] = p;
	}
}

int main()
{
	uint8_t plain[10000];
	uint8_t cipher[10000];
	size_t clen;

	srand(time(NULL));
	get_ciphertext(cipher, &clen);
	crack_plaintext(plain, cipher, clen);

	fwrite(plain, 1, clen, stdout);
	return 0;
}
