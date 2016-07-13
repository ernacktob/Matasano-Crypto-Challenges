#ifndef SERVER_H
#define SERVER_H

#include <stdlib.h>
#include <stdint.h>

#include "utils.h"

void server_process_request_proto1(const uint8_t *message, size_t len, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t mac[AES_BLOCK_SIZE]);
void server_process_request_proto2(const uint8_t *message, size_t len, const uint8_t mac[AES_BLOCK_SIZE]);
void server_init();

#endif
