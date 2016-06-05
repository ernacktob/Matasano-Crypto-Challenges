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
#define REPEAT_COUNT	50

int get_socket()
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof addr;
	int sockfd;
	int rc;
	int one = 1;

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

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
		perror("setsockopt");
		close(sockfd);
		return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0) {
		perror("setsockopt");
		close(sockfd);
		return -1;
	}

	rc = connect(sockfd, (struct sockaddr *)&addr, addrlen);

	if (rc != 0) {
		perror("connect");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

uint64_t get_average_delay(int *done, const char *get_request, size_t reqlen)
{
	char response[RESPONSE_LEN];
	struct timeval start, stop;
	uint64_t delay, avg_delay = 0;
	int sockfd;
	ssize_t rb;
	int i;

	for (i = 0; i < REPEAT_COUNT; i++) {
		sockfd = get_socket();

		if (sockfd < 0)
			return 0;

		if (send(sockfd, get_request, reqlen, 0) != reqlen) {
			perror("send");
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			return 0;
		}

		gettimeofday(&start, NULL);
		rb = recv(sockfd, response, sizeof response, 0);
		gettimeofday(&stop, NULL);

		delay = (uint64_t)(stop.tv_sec * 1000000 + stop.tv_usec) - (uint64_t)(start.tv_sec * 1000000 + start.tv_usec);
		avg_delay = (avg_delay * i + delay) / (i + 1);

		if (rb <= 0) {
			perror("recv");
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			return 0;
		}

		if (rb < strlen("HTTP/1.1 200")) {
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			return 0;
		}

		if (strncmp(response, "HTTP/1.1 200", strlen("HTTP/1.1 200")) == 0) {
			*done = 1;
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			return avg_delay;
		}

		usleep(1000);	/* Needed because TCP sockets go in TIME_WAIT state which means looping too fast
				   will leak ressources fot these sockets and eventually hangs... Unfortunately
				   this slows down the program. */
		close(sockfd);
	}

	return avg_delay;
}

int get_valid_mac(uint8_t *signature, size_t *siglen, const char *filename)
{
	char *get_request;
	size_t reqlen;
	size_t namelen;
	size_t i, j;
	uint16_t byte;
	uint64_t delays[256];
	uint64_t max_delay;
	uint8_t good_byte;
	int done;

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
			done = 0;
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

			delays[byte] = get_average_delay(&done, get_request, reqlen);

			if (delays[byte] == 0) {
				free(get_request);
				return -1;
			}

			if (done == 1) {
				++i;
				goto done;
			}
		}

		max_delay = 0;

		for (byte = 0; byte < 256; byte++) {
			if (max_delay < delays[byte]) {
				max_delay = delays[byte];
				good_byte = byte;
			}
		}

		if (max_delay == 0) {
			free(get_request);
			return 1;
		}

		signature[i] = good_byte;
	}

	free(get_request);
	return 1;

done:
	*siglen = i;
	free(get_request);
	return 0;
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


/*	int sockfd;
	for (i = 0; i < 100000; i++) {
		sockfd = get_socket();

		if (sockfd == -1)
			break;

		send(sockfd, "aaa\r\n", strlen("aaa\r\n"), 0);
		printf("%lu\n", i);
		while (recv(sockfd, &siglen, 1, 0) != 0);

		close(sockfd);
	}
*/
	return 0;
}
