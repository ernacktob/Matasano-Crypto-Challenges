#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/time.h>

#define IP		"127.0.0.1"
#define PORT		9000

#define MAX_SIGLEN	20
#define RESPONSE_LEN	100

int get_socket()
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof addr;
	int sockfd;
	int rc;

	memset(&addr, 0, sizeof addr);
	addr.sin_len = sizeof addr.sin_addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, IP, &addr.sin_addr.s_addr) != 1) {
		perror("inet_pton");
		return -1;
	}

	sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sockfd == -1) {
		perror("socket");
		return -1;
	}

	rc = connect(sockfd, (struct sockaddr *)&addr, addrlen);

	if (rc != 0) {
		perror("connect");
		return -1;
	}

	return sockfd;
}

int get_valid_mac(uint8_t *signature, size_t *siglen, const char *filename)
{
	char *get_request;
	char response[RESPONSE_LEN];
	size_t reqlen;
	size_t namelen;
	size_t i, j;
	uint16_t byte;
	ssize_t rb;
	struct timeval stop, start;
	uint64_t delays[256];
	uint64_t max_delay;
	uint8_t good_byte;
	int sockfd;

	memset(signature, 0, MAX_SIGLEN);
	namelen = strlen(filename);
	reqlen = strlen("GET /test?file=") + namelen + strlen("&signature=") + MAX_SIGLEN * 2 + strlen(" HTTP/1.1\r\n\r\n");

	get_request = malloc(reqlen);

	if (get_request == NULL) {
		perror("malloc");
		return -1;
	}

	for (i = 0; i < MAX_SIGLEN; i++) {
		for (byte = 0; byte < 256; byte++) {
			sockfd = get_socket();

			if (sockfd < 0)
				goto error;

			memset(get_request, 0, reqlen);
			signature[i] = (uint8_t)(byte & 0xff);
			snprintf(get_request, reqlen, "GET /test?file=%s&signature=", filename);

			for (j = 0; j < MAX_SIGLEN; j++)
				snprintf(get_request + strlen(get_request), reqlen - strlen(get_request), "%02x", signature[j]);

			strncat(get_request, " HTTP/1.1\r\n\r\n", reqlen - strlen(get_request));
			printf("Trying ");
			fwrite(get_request + strlen("GET /test?file=") + namelen + strlen("&signature="), 2 * MAX_SIGLEN, 1, stdout);
			printf("\r");
			fflush(stdout);

			if (send(sockfd, get_request, reqlen, 0) != reqlen) {
				perror("send");
				goto error;
			}

			gettimeofday(&start, NULL);
			rb = recv(sockfd, response, sizeof response, 0);
			gettimeofday(&stop, NULL);

			delays[byte] = (uint64_t)(stop.tv_sec * 1000000 + stop.tv_usec) - (uint64_t)(start.tv_sec * 1000000 + start.tv_usec);

			if (rb <= 0) {
				perror("recv");
				goto error;
			}

			if (rb < strlen("HTTP/1.1 200"))
				goto error;

			if (strncmp(response, "HTTP/1.1 200", strlen("HTTP/1.1 200")) == 0) {
				signature[i] = byte;
				++i;
				goto done;
			}

			close(sockfd);
		}

		max_delay = 0;

		for (byte = 0; byte < 256; byte++) {
			if (max_delay < delays[byte]) {
				max_delay = delays[byte];
				good_byte = byte;
			}
		}

		if (max_delay == 0)
			goto error;
		
		signature[i] = good_byte;
	}

	return 1;

done:
	*siglen = i;
	close(sockfd);
	return 0;

error:
	free(get_request);
	close(sockfd);
	return -1;
}

int main(int argc, const char *argv[])
{
	const char *filename = NULL;
	uint8_t signature[MAX_SIGLEN];
	size_t siglen, i;

	if (argc != 2) {
		printf("Usage: %s <file>\n", argv[0]);
		return 0;
	}

	filename = argv[1];

	if (get_valid_mac(signature, &siglen, filename) == 0) {
		printf("Found valid MAC: ");

		for (i = 0; i < siglen; i++)
			printf("%02x", signature[i]);

		printf("\n");
	} else {
		printf("Could not find valid file signature. Check that file exists.\n");
	}

	return 0;
}
