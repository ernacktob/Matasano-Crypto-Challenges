#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "client.h"
#include "server.h"
#include "utils.h"

static void xor_blocks(uint8_t *c, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		c[i] = a[i] ^ b[i];
}

void break_protocol_1()
{
	uint16_t victim_id = 1234;
	uint16_t my_id;
	uint8_t *message;
	size_t len;
	uint8_t iv[AES_BLOCK_SIZE], fake_iv[AES_BLOCK_SIZE];
	uint8_t mac[AES_BLOCK_SIZE];
	uint8_t modified_block[AES_BLOCK_SIZE + 1], delta_block[AES_BLOCK_SIZE + 1];	/* For the null char added in sprintf. Just ignore it. */

	my_id = client_get_id();
	message = client_generate_request_proto1(&len, iv, mac, my_id, 1000000);

	snprintf(modified_block, sizeof modified_block, "from=#{%05hu}&to", victim_id);
	xor_blocks(delta_block, modified_block, message, AES_BLOCK_SIZE);
	xor_blocks(fake_iv, iv, delta_block, AES_BLOCK_SIZE);
	memcpy(message, modified_block, AES_BLOCK_SIZE);

	printf("Protocol 1 server response:\n");
	server_process_request_proto1(message, len, fake_iv, mac);

	free(message);
}

void break_protocol_2()
{
	uint16_t target_id = 1234;
	uint16_t my_id;
	uint8_t *target_message, *my_message;
	size_t target_len, my_len;
	uint8_t target_mac[AES_BLOCK_SIZE], my_mac[AES_BLOCK_SIZE];
	uint8_t *extended_message;

	/* This part is more ambiguous. I don't think it can be solved
	 * without making some hand-waving in the server's parsing.
	 * We will first sign a valid transaction from our account
	 * to our own account for 1M spacebucks. We then obtain
	 * a valid message from the target (presumably obtained by
	 * sniffing network traffic), and concatenate our own message.
	 * In order for the MAC to remain the same, the first block of
	 * our message will be xored with the mac of the target message.
	 * This "simulates" an IV of 0 for our message, keeping the same
	 * MAC as a result.
	 *
	 * We have (message, mac) pairs (M, t) and (M', t'), and we generate
	 * the pair (M || (M'[0] ^ t) || M'[1..], t').
	 *
	 * Of course, this means there will be junk between the end of
	 * the target's transaction list and the beggining of ours,
	 * so a correct parsing implementation would reject that as invalid
	 * request. For the purpose of the challenge, we will assume the
	 * parsing implementation is very dumb...
	 * 
	 * This still has a slight change of failing if a semicolon appears as
	 * part of the junk data, because the parser will look for the
	 * transactions based on the semicolons. */
	my_id = client_get_id();
	my_message = client_generate_request_proto2(&my_len, my_mac, my_id, 1000000);
	target_message = client_capture_request_proto2(&target_len, target_mac, target_id);

	extended_message = malloc(target_len + my_len);
	memcpy(extended_message, target_message, target_len);
	xor_blocks(extended_message + target_len, my_message, target_mac, AES_BLOCK_SIZE);
	memcpy(extended_message + target_len + AES_BLOCK_SIZE, my_message + AES_BLOCK_SIZE, my_len - AES_BLOCK_SIZE);

	printf("Protocol 2 server response:\n");
	server_process_request_proto2(extended_message, target_len + my_len, my_mac);

	free(extended_message);
	free(target_message);
	free(my_message);
}

int main()
{
	srand(time(NULL));
	client_init();
	server_init();

	printf("Attacker account id: %05hu\n\n", client_get_id());

	break_protocol_1();
	printf("\n");
	break_protocol_2();

	return 0;
}
