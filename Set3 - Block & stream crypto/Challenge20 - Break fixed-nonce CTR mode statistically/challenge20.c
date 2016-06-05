#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
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

void get_ciphertexts(uint8_t cipher[][100], size_t len[])
{
	const char *b64str[] = {"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
				"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
				"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
				"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
				"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
				"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
				"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
				"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
				"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
				"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
				"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
				"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
				"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
				"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
				"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
				"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
				"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
				"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
				"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
				"U2hlIHJvZGUgdG8gaGFycmllcnM/",
				"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
				"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
				"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
				"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
				"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
				"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
				"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
				"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
				"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
				"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
				"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
				"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
				"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
				"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
				"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
				"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="};
	uint8_t plain[40][100];
	size_t plen[40];

	uint8_t password[AES_BLOCK_SIZE];
	const uint8_t nonce[AES_BLOCK_SIZE / 2] = {'\x00'};
	AES_KEY AESkey;

	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		password[i] = rand() % 256;

	for (i = 0; i < 40; i++) {
		if (b64decode(plain[i], &plen[i], b64str[i], strlen(b64str[i])) != 0) {
			printf("Invalid Base64 string.\n");
			return;
		}

		AES_set_encrypt_key(password, 128, &AESkey);
		aes_ctr_encrypt_decrypt(plain[i], cipher[i], plen[i], &AESkey, nonce);
		len[i] = plen[i];
	}
}

static int scorebyte(uint8_t c)
{
	if (c == '\t')
		return 0;

	if (isalpha(c))
		return 10;
	if (c == ' ')
		return 10;

	switch (c) {
		case '.':
		case ',':
			return 5;
		case ':':
		case '-':
		case '\'':
		case ';':
			return 2;
		default:
			return 0;
	}

	return 0;
}

static uint8_t get_key_byte(const uint8_t cipher[][100], const size_t len[], size_t index)
{
	int byte, best_byte = 0;
	int i;
	int score, max_score = 0;

	for (byte = 0; byte < 256; byte++) {
		score = 0;

		for (i = 0; i < 40; i++) {
			if (len[i] < index)
				continue;

			score += scorebyte(cipher[i][index] ^ (uint8_t)byte);

			if (cipher[i][index] ^ (uint8_t)byte == 0 && index == len[i])
				score += 100;
		}

		if (score > max_score) {
			best_byte = byte;
			max_score = score;
		}
	}

	return best_byte;
}

void decrypt_ciphertexts(uint8_t plain[][100], const uint8_t cipher[][100], const size_t len[])
{
	size_t index;
	int i;

	for (i = 0; i < 40; i++) {
		for (index = 0; index < len[i]; index++)
			plain[i][index] = cipher[i][index] ^ get_key_byte(cipher, len, index);
	}
}

int main()
{
	uint8_t plain[40][100];
	uint8_t cipher[40][100];
	size_t len[40];
	int i;

	srand(time(NULL));
	get_ciphertexts(cipher, len);
	decrypt_ciphertexts(plain, cipher, len);

	for (i = 0; i < 40; i++) {
		fwrite(plain[i], len[i], 1, stdout);
		printf("\n");
	}

	return 0;
}
