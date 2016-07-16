#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/aes.h>

#define BLOCK_SIZE	AES_BLOCK_SIZE

unsigned int collision_calls = 0;

typedef void (*compression_fn)(uint8_t out[BLOCK_SIZE], const uint8_t block[BLOCK_SIZE], const uint8_t key[BLOCK_SIZE]);
typedef void (*hash_fn)(uint8_t *hash, const uint8_t *message, size_t len, int init);

static void merkle_darmgard(const uint8_t *message, size_t mlen, uint8_t *state, size_t slen, compression_fn compress)
{
	uint8_t key[BLOCK_SIZE];
	uint8_t out[BLOCK_SIZE];
	uint8_t last_block[BLOCK_SIZE];
	size_t padlen;
	size_t i;

	assert(slen <= BLOCK_SIZE);
	memset(key, 0, sizeof key);

	for (i = 0; i < mlen / BLOCK_SIZE; i++) {
		memcpy(key, state, slen);
		compress(out, message + i * BLOCK_SIZE, key);
		memcpy(state, out, slen);
	}

	/* Pad last block with zeros. */
	if (mlen % BLOCK_SIZE != 0) {
		memset(last_block, 0, sizeof last_block);
		memcpy(last_block, message + i * BLOCK_SIZE, mlen - i * BLOCK_SIZE);
		memcpy(key, state, slen);
		compress(out, last_block, key);
		memcpy(state, out, slen);
	}
}

/* The compression function to be used (not really a compression, lol). */
static void aes_encrypt(uint8_t out[BLOCK_SIZE], const uint8_t block[BLOCK_SIZE], const uint8_t key[BLOCK_SIZE])
{
	AES_KEY aeskey;

	AES_set_encrypt_key(key, 128, &aeskey);
	AES_ecb_encrypt(block, out, &aeskey, AES_ENCRYPT);
}

static void hash_f(uint8_t *hash, const uint8_t *message, size_t len, int init)
{
	const size_t hlen = 2;

	if (init) {
		hash[0] = 0x12;
		hash[1] = 0x34;
	}

	merkle_darmgard(message, len, hash, hlen, aes_encrypt);
}

static void hash_g(uint8_t *hash, const uint8_t *message, size_t len, int init)
{
	const size_t hlen = 4;

	if (init) {
		hash[0] = 0xde;
		hash[1] = 0xad;
		hash[2] = 0xbe;
		hash[3] = 0xef;
	}

	merkle_darmgard(message, len, hash, hlen, aes_encrypt);
}

/* Concatenate f(x) and g(x). */
static void hash_h(uint8_t *hash, const uint8_t *message, size_t len, int init)
{
	const size_t hlen_f = 2;

	hash_f(hash, message, len, init);
	hash_g(hash + hlen_f, message, len, init);
}

/* If the state size is b bits, it will take 2^(b/2) attempts approximately to find a collision. */
int find_single_collision(uint8_t block1[BLOCK_SIZE], uint8_t block2[BLOCK_SIZE], int init, uint8_t *state, size_t hlen, hash_fn hash)
{
	/* Hash table used to detect duplicates.
	 * The hash table is indexed by the lowest 16-bits of hash value., into buckets.
	 * The values of 'i' that fall into these buckets are stored.
	 * For 32-bit hash, 2^16 attempts are expected, thus approximately 1 entry per bucket
	 * is expected. So checking for duplicate hashes is done by first getting the bucket,
	 * and comparing the hash of every entry in the bucket.
	 * I did that as a cheap alternative for an actual hash table implementation,
	 * but couldn't just use a single associative array because 2^32 bytes is too much memory... */
	static uint32_t hash_table[1 << 16][10];
	static uint8_t bucket_sizes[1 << 16] = {0};
	uint8_t block[BLOCK_SIZE] = {0};
	uint32_t value = 0, value2 = 0;
	uint32_t i;
	int k;

	assert(hlen <= 4);
	assert(BLOCK_SIZE >= 4);
	++collision_calls;

	/* wraparound... */
	for (i = 1; i != 0; i++) {
		/* Use previous hash as initial state (for multicollisions). */
		if (init == 0)
			memcpy(&value, state, hlen);

		memcpy(block, &i, sizeof (uint32_t));
		hash((uint8_t *)&value, block, sizeof block, init);

		/* Search bucket for collisions. */
		for (k = 0; k < bucket_sizes[value & 0xffff]; k++) {
			/* Use previous hash as initial state (for multicollisions). */
			if (init == 0)
				memcpy(&value2, state, hlen);

			memcpy(block, &(hash_table[value & 0xffff][k]), sizeof (uint32_t));
			hash((uint8_t *)&value2, block, sizeof block, init);

			/* We found a collision! */
			if (value2 == value) {
				/* Need to take into account the padding bytes in the block cipher. */
				memset(block1, 0, sizeof block1);
				memset(block2, 0, sizeof block2);
				memcpy(block1, &(hash_table[value & 0xffff][k]), sizeof (uint32_t));
				memcpy(block2, &i, sizeof (uint32_t));
				memcpy(state, &value, hlen);
				return 1;
			}
		}

		if (bucket_sizes[value & 0xffff] < 10)
			hash_table[value & 0xffff][bucket_sizes[value & 0xffff]++] = i;
	}

	return 0;
}

/* Find collision, but among messages obtainable from the given blocks. */
int find_single_collision_from_set(uint8_t *m1, uint8_t *m2, uint8_t (*blocks1)[BLOCK_SIZE], uint8_t (*blocks2)[BLOCK_SIZE], size_t nblocks, size_t hlen, hash_fn hash)
{
	static uint32_t hash_table[1 << 16][10];
	static uint8_t bucket_sizes[1 << 16] = {0};
	uint32_t value = 0, value2 = 0;
	uint32_t i, j;
	size_t k, n;

	assert(hlen <= 4);
	assert(BLOCK_SIZE >= 4);
	++collision_calls;

	/* Use each bit of i to indicate whether block1 or block2 is used. */
	for (i = 0; i < (1 << nblocks); i++) {
		for (k = 0; k < nblocks; k++) {
			if (((i >> k) & 0x1) == 0)
				memcpy(m1 + k * BLOCK_SIZE, blocks1[k], sizeof blocks1[k]);
			else
				memcpy(m1 + k * BLOCK_SIZE, blocks2[k], sizeof blocks2[k]);
		}

		hash((uint8_t *)&value, m1, nblocks * BLOCK_SIZE, 1);

		/* Search bucket for collisions. */
		for (n = 0; n < bucket_sizes[value & 0xffff]; n++) {
			j = hash_table[value & 0xffff][n];

			/* Copy corresponding m2. */
			for (k = 0; k < nblocks; k++) {
				if (((j >> k) & 0x1) == 0)
					memcpy(m2 + k * BLOCK_SIZE, blocks1[k], sizeof blocks1[k]);
				else
					memcpy(m2 + k * BLOCK_SIZE, blocks2[k], sizeof blocks2[k]);
			}

			hash((uint8_t *)&value2, m2, nblocks * BLOCK_SIZE, 1);

			/* We found a collision! */
			if (value2 == value)
				return 1;
		}

		if (bucket_sizes[value & 0xffff] < 10)
			hash_table[value & 0xffff][bucket_sizes[value & 0xffff]++] = i;
	}

	return 0;
}

/* blocks1, blocks2: pointers to arrays of size BLOCK_SIZE. */
int find_many_collisions(uint8_t (*blocks1)[BLOCK_SIZE], uint8_t (*blocks2)[BLOCK_SIZE], size_t n, size_t hlen, hash_fn hash)
{
	uint8_t state[4];
	size_t i;

	assert(hlen <= 4);

	if (find_single_collision(blocks1[0], blocks2[0], 1, state, hlen, hash) != 1)
		return 0;

	for (i = 1; i < n; i++) {
		if (find_single_collision(blocks1[i], blocks2[i], 0, state, hlen, hash) != 1)
			return i;
	}

	return n;
}

/* Generate 2^(b2/2) collisions in f ---> two of these will likely collide in g. */
int find_multicollision(uint8_t *m1, uint8_t *m2, size_t hlen_f, hash_fn hf, size_t hlen_g, hash_fn hg)
{
	/* b2 = 32 bits --> b2/2 = 16 bits --> need 2^16 collisions. Find 2^17 just in case */
	uint8_t blocks1[17][BLOCK_SIZE], blocks2[17][BLOCK_SIZE];
	uint8_t hash1[4], hash2[4];
	size_t max_len, min_len;
	unsigned int i, j;
	size_t k;

	max_len = (hlen_f < hlen_g ? hlen_g : hlen_f);
	min_len = (hlen_f < hlen_g ? hlen_f : hlen_g);

	/* Make sure both hashes fit in 4 bytes and b2 == 32 bits. */
	assert(max_len <= 4);

	/* Switch order in case f(x) is longer than g(x). */
	if (max_len == hlen_f) {
		hash_fn temp;
		hlen_f = hlen_g;
		hlen_g = max_len;
		temp = hf;
		hf = hg;
		hg = temp;
	}

	memset(blocks1, 0, sizeof blocks1);
	memset(blocks2, 0, sizeof blocks2);

	/* Use one more block to increase chances of finding multicollision. */
	if (find_many_collisions(blocks1, blocks2, (8 * hlen_g) / 2 + 1, hlen_f, hf) != (8 * hlen_g) / 2 + 1)
		return 0;

	if (find_single_collision_from_set(m1, m2, blocks1, blocks2, (8 * hlen_g) / 2 + 1, hlen_g, hg) != 1)
		return 0;
	
	return 1;
}

int main()
{
	uint8_t m1[BLOCK_SIZE * 17], m2[BLOCK_SIZE * 17];
	uint8_t hash1[6], hash2[6];
	int i;

	if (find_multicollision(m1, m2, 2, hash_f, 4, hash_g) != 1) {
		printf("Failed to find multicollision for f(x) and g(x).\n");
		return 1;
	}

	hash_h(hash1, m1, sizeof m1, 1);
	hash_h(hash2, m2, sizeof m2, 1);

	if (memcmp(hash1, hash2, 6) == 0) {
		printf("Found collision for h(x):\n");
		printf("hash = %02x%02x%02x%02x%02x%02x\n", hash1[0], hash1[1], hash1[2], hash1[3], hash1[4], hash1[5]);
		printf("m1 = \"");

		for (i = 0; i < sizeof m1; i++)
			printf("\\x%02x", m1[i]);

		printf("\"\n");
		printf("m2 = \"");

		for (i = 0; i < sizeof m2; i++)
			printf("\\x%02x", m2[i]);

		printf("\"\n");
		printf("Number of calls to collision functions: %u\n", collision_calls);
	} else {
		printf("Failed to find collision.\n");
	}

	return 0;
}
