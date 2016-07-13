#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "utils.h"

static uint8_t secret_key[AES_BLOCK_SIZE];
static uint16_t client_id;

static void client_sign(uint8_t mac[AES_BLOCK_SIZE], uint8_t iv[AES_BLOCK_SIZE], const char *message, size_t len)
{
	AES_KEY key;

	AES_set_encrypt_key(secret_key, 128, &key);
	cbc_mac(mac, message, len, &key, iv);
}

uint8_t *client_generate_request_proto1(size_t *len, uint8_t iv[AES_BLOCK_SIZE], uint8_t mac[AES_BLOCK_SIZE], uint16_t to_id, uint32_t amount)
{
	uint8_t *message;
	static char request[100];
	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		iv[i] = rand() % 256;

	snprintf(request, sizeof request, "from=#{%05hu}&to=#{%05hu}&amount=#{%09u}", client_id, to_id, amount);
	message = get_padded_string(len, request, strlen(request));

	if (message == NULL)
		return NULL;

	client_sign(mac, iv, message, *len);
	return message;
}

uint8_t *client_generate_request_proto2(size_t *len, uint8_t mac[AES_BLOCK_SIZE], uint16_t to_id, uint32_t amount)
{
	uint8_t *message;
	static char request[100];
	uint8_t iv[AES_BLOCK_SIZE];

	memset(iv, 0, sizeof iv);
	/* Make two transactions to get a semicolon in the list. The parser will skip the stuff before the semicolon... */
	snprintf(request, sizeof request, "from=#{%05hu}&tx_list=#{%05hu:%09hu;%05hu:%09u}", client_id, amount, client_id, to_id, amount);
	message = get_padded_string(len, request, strlen(request));

	if (message == NULL)
		return NULL;

	client_sign(mac, iv, message, *len);
	return message;
}

uint8_t *client_capture_request_proto2(size_t *len, uint8_t mac[AES_BLOCK_SIZE], uint16_t from_id)
{
	uint8_t *message;
	static char request[100];
	uint8_t iv[AES_BLOCK_SIZE];

	memset(iv, 0, sizeof iv);
	snprintf(request, sizeof request, "from=#{%05hu}&tx_list=#{%05hu:%09u}", from_id, 1, 42);
	message = get_padded_string(len, request, strlen(request));

	if (message == NULL)
		return NULL;

	client_sign(mac, iv, message, *len);
	return message;
}

uint16_t client_get_id()
{
	return client_id;
}

void client_init()
{
	const char *password = "YELLOW SUBMARINE";

	memcpy(secret_key, password, AES_BLOCK_SIZE);
	client_id = rand() % 65536;
}
