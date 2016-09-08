#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/aes.h>

#define BLOCK_SIZE	AES_BLOCK_SIZE

struct hash_index {
	uint32_t hash;
	size_t index;
};

typedef void (*compression_fn)(uint8_t out[BLOCK_SIZE], const uint8_t block[BLOCK_SIZE], const uint8_t key[BLOCK_SIZE]);
typedef void (*hash_fn)(uint8_t *hash, const uint8_t *message, size_t len, int init);
typedef void (*partial_hash_fn)(uint8_t *hash, const uint8_t *message, size_t len, int init, size_t nblocks);

static size_t hash_calls = 0;

static void merkle_damgard(const uint8_t *message, size_t mlen, uint8_t *state, size_t slen, compression_fn compress)
{
	uint8_t key[BLOCK_SIZE];
	uint8_t out[BLOCK_SIZE];
	uint8_t last_block[BLOCK_SIZE];
	size_t padlen;
	size_t i;

	assert(BLOCK_SIZE > 8);
	assert(sizeof mlen <= 8);
	assert(slen <= BLOCK_SIZE);
	++hash_calls;
	memset(key, 0, sizeof key);

	for (i = 0; i < mlen / BLOCK_SIZE; i++) {
		memcpy(key, state, slen);
		compress(out, message + i * BLOCK_SIZE, key);
		memcpy(state, out, slen);
	}

	/* Pad last block. */
	/* Paddig format is:
	 * 	append bit '1' after message
	 * 	append bit '0' until 8 bytes remain
	 * 		(if there were less than 8 to start with, add new block)
	 * 	in the last remaining 8 bytes, write message length mlen in little-endian. */
	if (BLOCK_SIZE - mlen % BLOCK_SIZE >= 8) {
		memset(last_block, 0, sizeof last_block);
		memcpy(last_block, message + i * BLOCK_SIZE, mlen % BLOCK_SIZE);
		last_block[mlen % BLOCK_SIZE] = 0x80;	/* Append bit '1'. */
		memcpy(last_block + sizeof last_block - 8, &mlen, sizeof mlen);	/* Append the length. */
		memcpy(key, state, slen);
		compress(out, last_block, key);
		memcpy(state, out, slen);
	} else {
		memset(last_block, 0, sizeof last_block);
		memcpy(last_block, message + i * BLOCK_SIZE, mlen % BLOCK_SIZE);
		last_block[mlen % BLOCK_SIZE] = 0x80;
		memcpy(key, state, slen);
		compress(out, last_block, key);
		memcpy(state, out, slen);
		memset(last_block, 0, sizeof last_block);
		memcpy(last_block + sizeof last_block - 8, &mlen, sizeof mlen);
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
	const size_t hlen = 4;

	if (init) {
		hash[0] = 0x12;
		hash[1] = 0x34;
		hash[2] = 0x56;
		hash[3] = 0x78;
	}

	merkle_damgard(message, len, hash, hlen, aes_encrypt);
}

static void merkle_damgard_no_padding(const uint8_t *message, size_t mlen, uint8_t *state, size_t slen, compression_fn compress, size_t nblocks)
{
	uint8_t key[BLOCK_SIZE];
	uint8_t out[BLOCK_SIZE];
	size_t padlen;
	size_t i;

	assert(BLOCK_SIZE > 8);
	assert(sizeof mlen <= 8);
	assert(slen <= BLOCK_SIZE);
	assert(mlen % BLOCK_SIZE == 0);
	assert(nblocks <= mlen / BLOCK_SIZE);
	++hash_calls;

	memset(key, 0, sizeof key);

	for (i = 0; i < nblocks; i++) {
		memcpy(key, state, slen);
		compress(out, message + i * BLOCK_SIZE, key);
		memcpy(state, out, slen);
	}
}

static void hash_intermediate_f(uint8_t *hash, const uint8_t *message, size_t len, int init, size_t nblocks)
{
	const size_t hlen = 4;

	assert(len % BLOCK_SIZE == 0);
	assert(nblocks <= len / BLOCK_SIZE);

	if (init) {
		hash[0] = 0x12;
		hash[1] = 0x34;
		hash[2] = 0x56;
		hash[3] = 0x78;
	}

	merkle_damgard_no_padding(message, len, hash, hlen, aes_encrypt, nblocks);
}

/* If the state size is b bits, it will take 2^(b/2) attempts approximately to find a collision. */
int find_single_collision(uint8_t block1[BLOCK_SIZE], uint8_t block2[BLOCK_SIZE], const uint8_t *state1, const uint8_t *state2, size_t hlen, partial_hash_fn hash)
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
	static uint8_t bucket_sizes[1 << 16];
	uint8_t block[BLOCK_SIZE] = {0};
	uint32_t value1 = 0, value2 = 0;
	uint32_t i;
	int k;

	assert(hlen <= 4);
	assert(BLOCK_SIZE >= 4);

	memset(bucket_sizes, 0, sizeof bucket_sizes);

	/* Build list of 2^(hlen/2) hashes for first state. */
	for (i = 0; i < 1 << (8 * (hlen / 2)); i++) {
		memcpy(&value1, state1, hlen);
		memcpy(block, &i, sizeof (uint32_t));
		hash((uint8_t *)&value1, block, sizeof block, 0, 1);

		if (bucket_sizes[value1 & 0xffff] < 10)
			hash_table[value1 & 0xffff][bucket_sizes[value1 & 0xffff]++] = i;
	}

	/* Find collision of hashes from second state into first state. */
	i = 1;

	while (i != 0) {
		memcpy(&value2, state2, hlen);
		memcpy(block, &i, sizeof (uint32_t));
		hash((uint8_t *)&value2, block, sizeof block, 0, 1);

		/* Search bucket for collisions. */
		for (k = 0; k < bucket_sizes[value2 & 0xffff]; k++) {
			memcpy(&value1, state1, hlen);
			memcpy(block, &(hash_table[value2 & 0xffff][k]), sizeof (uint32_t));
			hash((uint8_t *)&value1, block, sizeof block, 0, 1);

			/* We found a collision! */
			if (value1 == value2) {
				/* Need to take into account the padding bytes in the block cipher. */
				memset(block1, 0, sizeof block1);
				memset(block2, 0, sizeof block2);
				memcpy(block1, &(hash_table[value2 & 0xffff][k]), sizeof (uint32_t));
				memcpy(block2, &i, sizeof (uint32_t));
				return 1;
			}
		}

		++i;
	}

	return 0;
}

/* blocks1 should have k entries of size BLOCK_SIZE, while blocks2 should have entries of size 2^1 * BLOCK_SIZE, ..., 2^k * BLOCK_SIZE. */
int build_expandable_message(uint8_t blocks1[][BLOCK_SIZE], uint8_t blocks2[][BLOCK_SIZE << 16], size_t k, size_t hlen, partial_hash_fn hash)
{
	uint8_t state1[4], state2[4];
	size_t i;

	assert(hlen <= 4);

	hash(state1, NULL, BLOCK_SIZE, 1, 0);	/* Get the hash IV... */
	memcpy(state2, state1, hlen);

	for (i = k; i > 0; i--) {
		memset(blocks2[i - 1], 'a', BLOCK_SIZE << (i - 1));
		hash(state2, blocks2[i - 1], BLOCK_SIZE << (i - 1), 0, 1 << (i - 1));

		if (!find_single_collision(blocks1[i - 1], blocks2[i - 1] + (BLOCK_SIZE << (i - 1)), state1, state2, hlen, hash))
			return 1;

		hash(state1, blocks1[i - 1], BLOCK_SIZE, 0, 1);
		memcpy(state2, state1, hlen);
	}

	return 0;
}

void build_hash_map(struct hash_index hashmap[][10], size_t bucket_counts[], const uint8_t M[], size_t k, size_t hlen, partial_hash_fn hash)
{
	uint8_t state[4];
	uint16_t key;
	uint32_t value;
	size_t i;

	assert(hlen <= 4);

	/* Use a hash map with 2^16 buckets with max 10 entries each (count entries in buckets with bucket_counts array. */
	memset(bucket_counts, 0, 1 << k);
	hash(state, NULL, BLOCK_SIZE, 1, 0);	/* Get the hash IV... */

	for (i = 0; i < (1 << k); i++) {
		hash(state, M + i * BLOCK_SIZE, BLOCK_SIZE, 0, 1);

		/* Only store hashes from index k + 1 onwards.
		 * Colliding with previous ones is not helpful because we can't create
		 * an expandable message of length less than k. */
		if (i < k)
			continue;

		key = state[0] + (state[1] << 8);
		value = state[0] + (state[1] << 8) + (state[2] << 16) + (state[3] << 24);
		assert(bucket_counts[key] < 10);
		hashmap[key][bucket_counts[key]].hash = value;
		hashmap[key][bucket_counts[key]++].index = i;
	}
}

int find_bridge(uint8_t bridge[BLOCK_SIZE], size_t *index, struct hash_index hashmap[][10], size_t bucket_counts[], const uint8_t hfinal[], size_t hlen, partial_hash_fn hash)
{
	uint8_t state[4];
	uint16_t key;
	uint32_t value;
	uint64_t n;
	size_t j;

	assert(hlen <= 4);
	memset(bridge, 0, BLOCK_SIZE);

	/* Try values for bridge until a collision is found with hash in the hashmap. */
	/* wrap around... */
	for (n = 1; n != 0; n++) {
		memcpy(state, hfinal, hlen);
		*(uint64_t *)bridge = n;
		hash(state, bridge, BLOCK_SIZE, 0, 1);

		key = state[0] + (state[1] << 8);
		value = state[0] + (state[1] << 8) + (state[2] << 16) + (state[3] << 24);

		for (j = 0; j < bucket_counts[key]; j++) {
			if (hashmap[key][j].hash == value) {
				*index = hashmap[key][j].index;
				return 1;
			}
		}
	}

	return 0;
}

void build_prefix(uint8_t *prefix, size_t nblocks, size_t k, uint8_t E1[][BLOCK_SIZE], uint8_t E2[][BLOCK_SIZE << 16])
{
	size_t i;
	int bit;

	nblocks -= k;	/* Expandable messages range from k to k + 2^k - 1. get the +k out. */
	i = 0;

	for (bit = k; bit > 0; bit--) {
		if (nblocks & (1 << (bit - 1))) {
			memcpy(prefix + i, E2[bit - 1], BLOCK_SIZE + (BLOCK_SIZE << (bit - 1)));
			i += (BLOCK_SIZE + (BLOCK_SIZE << (bit - 1)));
		} else {
			memcpy(prefix + i, E1[bit - 1], BLOCK_SIZE);
			i += BLOCK_SIZE;
		}
	}

	assert(i == BLOCK_SIZE * (nblocks + k));
}

int main()
{
	static uint8_t M[BLOCK_SIZE << 16];
	static uint8_t second_M[BLOCK_SIZE << 16];
	uint8_t hash_M[4], hash_second_M[4];

	static uint8_t E1[16][BLOCK_SIZE];
	static uint8_t E2[16][BLOCK_SIZE << 16];
	static uint8_t prefix[BLOCK_SIZE << 16];
	static struct hash_index hashmap[1 << 16][10];
	static size_t bucket_counts[1 << 16];
	uint8_t expandable1[16 * BLOCK_SIZE];
	uint8_t hfinal[4];
	uint8_t bridge[BLOCK_SIZE];
	size_t index;

	size_t i;

	/* This is the message we want to find a second preimage of. */
	memset(M, 'X', sizeof M);

	/* Use a hash length of 32 bits (4 bytes) and block size of 16 bytes. */
	if (build_expandable_message(E1, E2, 16, 4, hash_intermediate_f) != 0) {
		printf("Failed to build expandable message.\n");
		return 0;
	}

	build_hash_map(hashmap, bucket_counts, M, 16, 4, hash_intermediate_f);

	/* Get the expandable message blocks into a contiguous array. */
	for (i = 0; i < 16; i++)
		memcpy(expandable1 + (16 - i - 1) * BLOCK_SIZE, E1[i], BLOCK_SIZE);

	/* Get final state after hashing expandable message. */
	hash_intermediate_f(hfinal, NULL, BLOCK_SIZE, 1, 0);	/* Get hash IV. */
	hash_intermediate_f(hfinal, expandable1, 16 * BLOCK_SIZE, 0, 16);

	if (!find_bridge(bridge, &index, hashmap, bucket_counts, hfinal, 4, hash_intermediate_f)) {
		printf("Failed to find bridge.\n");
		return 0;
	}

	build_prefix(prefix, index, 16, E1, E2);
	
	/* Concatenate prefix || bridge || M[i] || ... || M[len(M) - 1] to get collision. */
	memcpy(second_M, prefix, index * BLOCK_SIZE);
	memcpy(second_M + index * BLOCK_SIZE, bridge, BLOCK_SIZE);
	memcpy(second_M + (index + 1) * BLOCK_SIZE, M + (index + 1) * BLOCK_SIZE, BLOCK_SIZE * ((1 << 16) - index - 1));

	hash_f(hash_M, M, sizeof M, 1);
	hash_f(hash_second_M, second_M, sizeof second_M, 1);

	if (memcmp(hash_M, hash_second_M, sizeof hash_M) != 0) {
		printf("Failed to find second preimage.\n");
		return 0;
	}

	printf("Successfully found second preimage for f(x).\n");
	printf("f(M1):\t%02x%02x%02x%02x\n", hash_M[0], hash_M[1], hash_M[2], hash_M[3]);
	printf("f(M2):\t%02x%02x%02x%02x\n", hash_second_M[0], hash_second_M[1], hash_second_M[2], hash_second_M[3]);
	printf("M1: \"");

	for (i = 0; i < 100; i++)
		printf("\\x%02x", M[i]);

	printf("...");

	for (i = sizeof M - 100; i < sizeof M; i++)
		printf("\\x%02x", M[i]);

	printf("\"\n");
	printf("M2: \"");

	for (i = 0; i < 100; i++)
		printf("\\x%02x", second_M[i]);

	printf("...");

	for (i = sizeof second_M - 100; i < sizeof second_M; i++)
		printf("\\x%02x", second_M[i]);

	printf("\"\n");
	printf("Total message length: %lu\n", sizeof M);
	printf("Number of hash computations: %lu\n", hash_calls);

	return 0;
}
