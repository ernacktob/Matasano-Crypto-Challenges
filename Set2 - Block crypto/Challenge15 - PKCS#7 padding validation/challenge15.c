#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 16

int PKCS7_Unpad(uint8_t *res, size_t *len, const uint8_t *string, size_t padded_len, size_t block_size)
{
	uint8_t pad;
	size_t i;

	pad = string[padded_len - 1];

	if (pad == 0 || pad > block_size || padded_len == 0 || padded_len % block_size)
		return 1;

	for (i = padded_len - 1; i >= padded_len - pad; i--) {
		if (string[i] != pad)
			return 1;
	}

	*len = padded_len - pad;
	memcpy(res, string, *len);
	return 0;
}

int main()
{
	const uint8_t *padded_string = "ICE ICE BABY\x04\x04\x04\x04";
	uint8_t unpadded_string[100];
	size_t len;

	if (PKCS7_Unpad(unpadded_string, &len, padded_string, strlen(padded_string), BLOCK_SIZE) != 0) {
		printf("Bad padding.\n");
		return 0;
	}

	fwrite(unpadded_string, len, 1, stdout);
	printf("\n");
	return 0;
}
