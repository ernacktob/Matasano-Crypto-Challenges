#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define BLOCK_SIZE 10

void PKCS7_Padding(uint8_t *data, size_t len, size_t blocklen)
{
	size_t i;

	for (i = len; i < len + (blocklen - len % blocklen); i++)
		data[i] = blocklen - len % blocklen;
}

int main()
{
	uint8_t data[2 * BLOCK_SIZE];
	size_t i;

	memcpy(data, "YELLOW SUBMARINE", strlen("YELLOW SUBMARINE"));
	PKCS7_Padding(data, strlen("YELLOW SUBMARINE"), BLOCK_SIZE);

	for (i = 0; i < sizeof data; i++) {
		if (isprint(data[i]))
			printf("%c", data[i]);
		else
			printf("\\x%02x", data[i]);
	}

	printf("\n");
	return 0;
}
