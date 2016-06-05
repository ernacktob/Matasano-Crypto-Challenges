#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha-1.h"

int sha1_mac(const uint8_t *message, size_t len, uint32_t mac[5])
{
	const char *key = "Th1$_Is_@_s3cRet!";
	uint8_t *modified_message;

	modified_message = malloc(strlen(key) + len);

	if (modified_message == NULL)
		return -1;

	memcpy(modified_message, key, strlen(key));
	memcpy(modified_message + strlen(key), message, len);

	if (sha1_hash(modified_message, 8 * (strlen(key) + len), mac) != 0) {
		free(modified_message);
		return -1;
	}

	free(modified_message);
	return 0;
}

int check_authentication(const uint8_t *message, size_t len, const uint32_t mac[5])
{
	uint32_t calc_mac[5];
	int i;

	if (sha1_mac(message, len, calc_mac) != 0)
		return -1;

	if (memcmp(calc_mac, mac, sizeof mac) != 0)
		return 1;

	return 0;
}

int main()
{
	const char *message = "This is a test message";
	const char *fake = "THis is a test message";
	uint32_t mac[5];

	if (sha1_mac(message, strlen(message), mac) != 0) {
		printf("Message authentication failed.\n");
		return 0;
	}

	if (check_authentication(message, strlen(message), mac) != 0)
		printf("Real message MAC authentication failed.\n");
	else
		printf("Real message MAC authentication succeeded.\n");

	if (check_authentication(fake, strlen(fake), mac) != 0)
		printf("Fake message MAC authentication failed.\n");
	else
		printf("Fake message MAC authentication succeeded.\n");

	return 0;
}
