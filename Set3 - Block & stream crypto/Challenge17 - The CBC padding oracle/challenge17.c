#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/aes.h>

typedef int (*padding_oracle_fn)(const uint8_t *, size_t, const uint8_t *);
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

static uint8_t *encrypt_string(size_t *clen, const uint8_t *string, size_t len, const uint8_t *iv)
{
	uint8_t *cipher;
	uint8_t *padded_string;
	size_t i;
	AES_KEY key;

	padded_string = malloc(len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE);

	if (padded_string == NULL)
		return NULL;

	cipher = malloc(len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE);

	if (cipher == NULL) {
		free(padded_string);
		return NULL;
	}

	memcpy(padded_string, string, len);
	PKCS7_Padding(padded_string, len, AES_BLOCK_SIZE);

	AES_set_encrypt_key(random_bytes, 128, &key);
	aes_cbc_encrypt(padded_string, cipher, len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE, &key, iv);

	free(padded_string);
	*clen = len + AES_BLOCK_SIZE - len % AES_BLOCK_SIZE;
	return cipher;
}

uint8_t *random_encrypt(size_t *clen, uint8_t *iv)
{
	const char *strings[] = {"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
				 "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
				 "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
				 "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
				 "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
				 "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
				 "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
				 "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
				 "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
				 "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};
	const char *s;
	size_t i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		iv[i] = rand() % 256;

	s = strings[rand() % 10];
	return encrypt_string(clen, s, strlen(s), iv);
}

int consume_ciphertext(const uint8_t *cipher, size_t clen, const uint8_t *iv)
{
	uint8_t *plain;
	size_t i;
	int valid;
	AES_KEY key;

	plain = malloc(clen);

	if (plain == NULL)
		return -1;

	AES_set_decrypt_key(random_bytes, 128, &key);
	aes_cbc_decrypt(cipher, plain, clen, &key, iv);

	valid = PKCS7_Valid_Padding(plain, clen, AES_BLOCK_SIZE);
	free(plain);

	return valid;
}

static int is_last_byte_01(uint8_t *prev_block, const uint8_t *iv, padding_oracle_fn padding_oracle)
{
	int i;

	for (i = 0; i < 256; i++) {
		prev_block[AES_BLOCK_SIZE - 2] = (uint8_t)i;

		if (!padding_oracle(prev_block, 2 * AES_BLOCK_SIZE, iv))
			return 0;
	}

	return 1;
}

static uint8_t find_last_byte(const uint8_t *prev_block, const uint8_t *iv, padding_oracle_fn padding_oracle)
{
	uint8_t modified_block[2 * AES_BLOCK_SIZE];
	uint8_t value;
	uint32_t i;

	memcpy(modified_block, prev_block, 2 * AES_BLOCK_SIZE);
	value = modified_block[AES_BLOCK_SIZE - 1];

	for (i = 0; i < 256; i++) {
		modified_block[AES_BLOCK_SIZE - 1] = value ^ (uint8_t)i;

		if (is_last_byte_01(modified_block, iv, padding_oracle))
			return 0x01 ^ (uint8_t)i;
	}

	return 0;
}

static uint8_t find_byte_at_index(size_t index, const uint8_t *decrypted_block, const uint8_t *prev_block, const uint8_t *iv, padding_oracle_fn padding_oracle)
{
	uint8_t modified_block[2 * AES_BLOCK_SIZE];
	uint8_t value;
	uint32_t i;

	memcpy(modified_block, prev_block, 2 * AES_BLOCK_SIZE);

	for (i = AES_BLOCK_SIZE - 1; i > index; i--)
		modified_block[i] ^= (decrypted_block[i] ^ (AES_BLOCK_SIZE - index));

	value = modified_block[index];

	for (i = 0; i < 256; i++) {
		modified_block[index] = value ^ (uint8_t)i;

		if (padding_oracle(modified_block, 2 * AES_BLOCK_SIZE, iv))
			return (uint8_t)(AES_BLOCK_SIZE - index) ^ (uint8_t)i;
	}

	return 0;
}

static void decrypt_block(uint8_t *decrypted_block, const uint8_t *prev_block, const uint8_t *iv, padding_oracle_fn padding_oracle)
{
	size_t index;

	decrypted_block[AES_BLOCK_SIZE - 1] = find_last_byte(prev_block, iv, padding_oracle);

	for (index = AES_BLOCK_SIZE - 1; index > 0; index--)
		decrypted_block[index - 1] = find_byte_at_index(index - 1, decrypted_block, prev_block, iv, padding_oracle);
}

uint8_t *decrypt_padding_oracle(const uint8_t *cipher, size_t clen, const uint8_t *iv, padding_oracle_fn padding_oracle)
{
	uint8_t ivblock[2 * AES_BLOCK_SIZE];
	uint8_t *plain;
	size_t block;

	if (clen % AES_BLOCK_SIZE)
		return NULL;

	plain = malloc(clen);

	if (plain == NULL)
		return NULL;

	memcpy(ivblock, iv, AES_BLOCK_SIZE);
	memcpy(ivblock + AES_BLOCK_SIZE, cipher, AES_BLOCK_SIZE);

	decrypt_block(plain, ivblock, iv, padding_oracle);

	for (block = 1; block < clen / AES_BLOCK_SIZE; block++)
		decrypt_block(plain + block * AES_BLOCK_SIZE, cipher + (block - 1) * AES_BLOCK_SIZE, iv, padding_oracle);

	return plain;
}

int main()
{
	uint8_t *decrypted_string;
	size_t plen;

	uint8_t *encrypted_string;
	uint8_t iv[AES_BLOCK_SIZE];
	size_t clen;

	srand(time(NULL));
	gen_random_key();

	encrypted_string = random_encrypt(&clen, iv);
	decrypted_string = decrypt_padding_oracle(encrypted_string, clen, iv, consume_ciphertext);
	plen = clen - decrypted_string[clen - 1];

	fwrite(decrypted_string, plen, 1, stdout);
	printf("\n");

	free(encrypted_string);
	free(decrypted_string);
	return 0;
}
