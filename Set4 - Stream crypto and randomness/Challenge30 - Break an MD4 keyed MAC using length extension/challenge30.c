#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "md4.h"

static uint8_t key[20];
static size_t keylen;

static void gen_secret_key()
{
	size_t i;

	keylen = 1 + rand() % 20;

	for (i = 0; i < keylen; i++)
		key[i] = rand() & 0xff;
}

static int md4_mac(const uint8_t *message, size_t len, uint32_t mac[4])
{
	uint8_t *modified_message;

	modified_message = malloc(keylen + len);

	if (modified_message == NULL)
		return -1;

	memcpy(modified_message, key, keylen);
	memcpy(modified_message + keylen, message, len);

	if (md4_hash(modified_message, 8 * (keylen + len), mac) != 0) {
		free(modified_message);
		return -1;
	}

	free(modified_message);
	return 0;
}

static int check_authentication(const uint8_t *message, size_t len, const uint32_t mac[4])
{
	uint32_t calc_mac[4];
	int i;

	if (md4_mac(message, len, calc_mac) != 0)
		return -1;

	if (memcmp(calc_mac, mac, sizeof mac) != 0)
		return 1;

	return 0;
}

int check_admin(const uint8_t *message, size_t len, const uint32_t mac[4])
{
	const char *admin_str = ";admin=true";

	if (check_authentication(message, len, mac) != 0)
		return 0;

	if (memmem(message, len, admin_str, strlen(admin_str)) == NULL)
		return 0;

	return 1;
}

const uint8_t *get_url(size_t *urllen, uint32_t mac[4])
{
	const char *url = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

	*urllen = strlen(url);

	if (md4_mac(url, *urllen, mac) != 0) {
		perror("md4_mac failed");
		return NULL;
	}

	return url;
}

static uint8_t *compute_padding(size_t *padlen, size_t mlen)
{
	uint8_t *padding;
	uint64_t ml;
	uint64_t rem = (64 - ((mlen + 1) % 64) + 56) % 64;

	*padlen = 1 + rem + 8;
	padding = calloc(*padlen, 1);

	if (padding == NULL)
		return NULL;

	ml = 8 * mlen;
	padding[0] = 0x80;
	memcpy(padding + *padlen - 8, &ml, 8);

	return padding;
}

uint8_t *get_length_extended_url(size_t *newlen, uint32_t new_mac[4], const uint8_t *url, size_t urllen, const uint32_t mac[4], const uint8_t *append, size_t appendlen)
{
	uint8_t *new_url = NULL;
	uint8_t *padding;
	size_t padlen, klen;

	for (klen = 0; klen < 20; klen++) {
		padding = compute_padding(&padlen, klen + urllen);

		if (padding == NULL)
			return NULL;

		new_url = malloc(urllen + padlen + appendlen);

		if (new_url == NULL) {
			free(padding);
			return NULL;
		}

		memcpy(new_url, url, urllen);
		memcpy(new_url + urllen, padding, padlen);
		memcpy(new_url + urllen + padlen, append, appendlen);

		*newlen = urllen + padlen + appendlen;

		if (md4_update(append, 8 * appendlen, mac, 8 * (klen + urllen + padlen), new_mac) != 0) {
			free(padding);
			free(new_url);
			return NULL;
		}

		free(padding);

		if (check_authentication(new_url, *newlen, new_mac) != 0)
			free(new_url);
		else
			break;
	}

	return new_url;
}

int main()
{
	const uint8_t *url = NULL;
	size_t urllen;
	uint32_t mac[4];

	uint8_t *new_url;
	size_t newlen;
	uint32_t new_mac[4];

	srand(time(NULL));
	gen_secret_key();

	url = get_url(&urllen, mac);

	if (check_admin(url, urllen, mac)) {
		printf("You are admin already, WTF???\n");
		return 0;
	} else {
		printf("You are not yet admin.\n");
	}

	new_url = get_length_extended_url(&newlen, new_mac, url, urllen, mac, ";admin=true", strlen(";admin=true"));

	if (check_admin(new_url, newlen, new_mac))
		printf("Congratz, you are now admin!\n");
	else
		printf("Still not admin :(\n");

	free(new_url);
	return 0;
}
