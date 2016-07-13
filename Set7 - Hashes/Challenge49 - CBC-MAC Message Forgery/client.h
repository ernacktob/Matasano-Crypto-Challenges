#ifndef CLIENT_H
#define CLIENT_H

#include <stdlib.h>
#include <stdint.h>

#include "utils.h"

uint8_t *client_generate_request_proto1(size_t *len, uint8_t iv[AES_BLOCK_SIZE], uint8_t mac[AES_BLOCK_SIZE], uint16_t to_id, uint32_t amount);
uint8_t *client_generate_request_proto2(size_t *len, uint8_t mac[AES_BLOCK_SIZE], uint16_t to_id, uint32_t amount);
uint8_t *client_capture_request_proto2(size_t *len, uint8_t mac[AES_BLOCK_SIZE], uint16_t from_id);
uint16_t client_get_id();
void client_init();

#endif
