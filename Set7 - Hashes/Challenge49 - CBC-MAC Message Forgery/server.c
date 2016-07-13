#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "utils.h"

static uint8_t secret_key[AES_BLOCK_SIZE];

struct transaction {
	uint16_t to_id;
	uint32_t amount;
};

static int parse_message_proto1(const uint8_t *request, size_t len, uint16_t *from_id, struct transaction *trans)
{
	char *request_string;
	size_t i;

	for (i = 0; i < len; i++) {
		if (request[i] == '\0')
			return -1;
	}

	request_string = malloc(len + 1);

	if (request_string == NULL)
		return -1;

	memcpy(request_string, request, len);
	request_string[len] = '\0';

	if (sscanf(request_string, "from=#{%05hu}&to=#{%05hu}&amount=#{%09u}", from_id, &(trans->to_id), &(trans->amount)) != 3) {
		free(request_string);
		return -1;
	}

	free(request_string);
	return 0;
}

static int parse_message_proto2(const uint8_t *request, size_t len, uint16_t *from_id, struct transaction **tx_list, size_t *count)
{
	char *request_string;
	const char *ptr;
	char *transactions;
	size_t i;
	size_t mem;
	struct transaction *temp;
	uint16_t to_id;
	uint32_t amount;

	for (i = 0; i < len; i++) {
		if (request[i] == '\0')
			return -1;
	}

	request_string = malloc(len + 1);

	if (request_string == NULL)
		return -1;

	memcpy(request_string, request, len);
	request_string[len] = '\0';

	transactions = malloc(len);

	if (transactions == NULL) {
		free(request_string);
		return -1;
	}

	/* deliberately weaken the sanity checks to make challenge solvable */
/*	if (sscanf(request_string, "from=#{%05hu}&tx_list=#{%[^}]}", from_id, transactions) != 2) { */
	if (sscanf(request_string, "from=#{%05hu}&tx_list=#{%s}", from_id, transactions) != 2) {
		free(transactions);
		free(request_string);
		return -1;
	}

	/* Remove the last '}'. This wouldn't be needed if proper parsing was done above. */
	if (transactions[strlen(transactions) - 1] == '}')
		transactions[strlen(transactions) - 1] = '\0';

	*tx_list = malloc(sizeof (struct transaction));

	if (*tx_list == NULL) {
		free(transactions);
		free(request_string);
		return -1;
	}

	if (sscanf(transactions, "%05hu:%09u", &((*tx_list)[0].to_id), &((*tx_list)[0].amount)) != 2) {
		free(*tx_list);
		free(transactions);
		free(request_string);
		return -1;
	}

	mem = 1;
	i = 0;
	ptr = transactions + 15;

	while (ptr < transactions + strlen(transactions)) {
		/* deliberately weaken sanity checks to make challenge solvable. */
/*		if (sscanf(ptr, ";%05hu:%09u", &to_id, &amount) != 2) { */
		if ((sscanf(ptr, "%*[^;];%05hu:%09u", &to_id, &amount) != 2) &&
		    (sscanf(ptr, ";%05hu:%09u", &to_id, &amount) != 2)) {
			free(*tx_list);
			free(transactions);
			free(request_string);
			return -1;
		}

		++i;

		/* We don't know the number of transactions initially,
		 * so we dynamically reallocate array size if there is
		 * no more room. */
		if (i == mem) {
			mem *= 2;
			temp = realloc(*tx_list, mem * sizeof (struct transaction));

			if (temp == NULL) {
				free(*tx_list);
				free(transactions);
				free(request_string);
				return -1;
			}

			*tx_list = temp;
		}

		(*tx_list)[i].to_id = to_id;
		(*tx_list)[i].amount = amount;

		/* move to next ocurrence of ';' to skip junk.
		 * again, this is deliberately bad parsing... */
		ptr = strchr(ptr, ';');
		ptr += 16;
	}

	free(transactions);
	free(request_string);
	*count = i + 1;

	return 0;
}

void server_process_request_proto1(const uint8_t *message, size_t len, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t mac[AES_BLOCK_SIZE])
{
	uint16_t from_id;
	struct transaction trans;
	uint8_t *request;
	size_t reqlen;
	uint8_t computed_mac[AES_BLOCK_SIZE];
	AES_KEY key;

	AES_set_encrypt_key(secret_key, 128, &key);
	cbc_mac(computed_mac, message, len, &key, iv);

	if (memcmp(computed_mac, mac, AES_BLOCK_SIZE) != 0) {
		printf("Error: Invalid MAC.\n");
		return;
	}

	request = get_unpadded_string(&reqlen, message, len);

	if (parse_message_proto1(request, reqlen, &from_id, &trans) != 0) {
		printf("Error: Invalid request.\n");
		free(request);
		return;
	}

	free(request);
	printf("Transferred %u spacebucks from account %05hu to account %05hu.\n", trans.amount, from_id, trans.to_id);
}

void server_process_request_proto2(const uint8_t *message, size_t len, const uint8_t mac[AES_BLOCK_SIZE])
{
	uint16_t from_id;
	struct transaction *tx_list;
	size_t count, i;
	uint8_t *request;
	size_t reqlen;
	uint8_t computed_mac[AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	AES_KEY key;

	memset(iv, 0, sizeof iv);
	AES_set_encrypt_key(secret_key, 128, &key);
	cbc_mac(computed_mac, message, len, &key, iv);

	if (memcmp(computed_mac, mac, AES_BLOCK_SIZE) != 0) {
		printf("Error: Invalid MAC.\n");
		return;
	}

	request = get_unpadded_string(&reqlen, message, len);

	if (parse_message_proto2(request, reqlen, &from_id, &tx_list, &count) != 0) {
		printf("Error: Invalid request.\n");
		free(request);
		return;
	}

	free(request);

	for (i = 0; i < count; i++)
		printf("Transferred %u spacebucks from account %05hu to account %05hu.\n", tx_list[i].amount, from_id, tx_list[i].to_id);

	free(tx_list);
}

void server_init()
{
	const char *password = "YELLOW SUBMARINE";

	memcpy(secret_key, password, AES_BLOCK_SIZE);
}
