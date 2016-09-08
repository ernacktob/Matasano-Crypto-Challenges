#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#include <openssl/aes.h>

#define BLOCK_SIZE	AES_BLOCK_SIZE
#define HASH_LENGTH	4
#define MAX_BUCKETS	(1 << 16)
#define BUCKET_SIZE	10
#define PREFIX_BLOCKS	5

struct HashNode {
	uint8_t state[HASH_LENGTH];
	uint8_t block[BLOCK_SIZE];
	struct HashNode *parent;
};

struct HashTree {
	size_t k;
	struct HashNode **nodes;
};

typedef void (*compression_fn)(uint8_t out[BLOCK_SIZE], const uint8_t block[BLOCK_SIZE], const uint8_t key[BLOCK_SIZE]);
typedef void (*hash_fn)(uint8_t *hash, const uint8_t *message, size_t len, int init);
typedef void (*partial_hash_fn)(uint8_t *hash, const uint8_t *message, size_t len, int init, size_t nblocks);

struct hash_value {
	uint8_t hash[HASH_LENGTH];
	uint8_t block[BLOCK_SIZE];
	size_t index;
};

static struct hash_value buckets[MAX_BUCKETS][BUCKET_SIZE];
static size_t bucket_counts[MAX_BUCKETS];

static unsigned int hash_calls = 0;

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

	++hash_calls;
	merkle_damgard_no_padding(message, len, hash, hlen, aes_encrypt, nblocks);
}

static void init_buckets()
{
	memset(bucket_counts, 0, sizeof bucket_counts);
}

static void add_to_buckets(const uint8_t hash[HASH_LENGTH], const uint8_t block[BLOCK_SIZE], size_t index)
{
	uint16_t key;
	uint32_t value;

	assert(HASH_LENGTH <= 4);
	assert(MAX_BUCKETS <= (1 << 16));

	value = hash[0] + (hash[1] << 8) + (hash[2] << 16) + (hash[3] << 24);
	key = value & 0xffff;

	if (bucket_counts[key] < BUCKET_SIZE) {
		memcpy(buckets[key][bucket_counts[key]].hash, hash, HASH_LENGTH);
		memcpy(buckets[key][bucket_counts[key]].block, block, BLOCK_SIZE);
		buckets[key][bucket_counts[key]].index = index;
		++bucket_counts[key];
	}
}

static int search_buckets(const uint8_t hash[HASH_LENGTH], uint8_t block[BLOCK_SIZE], size_t *index)
{
	uint16_t key;
	uint32_t value;
	size_t k;

	assert(HASH_LENGTH <= 4);
	assert(MAX_BUCKETS <= (1 << 16));

	value = hash[0] + (hash[1] << 8) + (hash[2] << 16) + (hash[3] << 24);
	key = value & 0xffff;

	for (k = 0; k < bucket_counts[key]; k++) {
		if (memcmp(buckets[key][k].hash, hash, HASH_LENGTH) == 0) {
			memcpy(block, buckets[key][k].block, BLOCK_SIZE);
			*index = buckets[key][k].index;
			return 1;
		}
	}

	return 0;
}

static void print_hex(const uint8_t *data, size_t len)
{
	size_t i;
	uint8_t c;

	for (i = 0; i < len; i++) {
		c = data[i];

		if (c < 32 || c >= 127)
			printf("\\x%02hhx", c);
		else if (c == '\\')
			printf("\\\\");
		else
			printf("%c", (char)c);
	}
}

static const char *get_results()
{
	static char results[PREFIX_BLOCKS * BLOCK_SIZE];

	/* Note: NULL byte included in total length. */
	snprintf(results, sizeof results, "The scores for this baseball season:   %d-%d, %d-%d, %d-%d, %d-%d, %d-%d, %d-%d, %d-%d, %d-%d.\n",
			rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10,
			rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10, rand() % 10);

	return results;
}

void destroy_diamond_structure(struct HashTree *tree, size_t i)
{
	size_t j;

	for (j = 0; j < i; j++)
		free(tree->nodes[j]);

	free(tree->nodes);
}

int build_diamond_structure(struct HashTree *tree, size_t k, partial_hash_fn hash)
{
	size_t i, j, p;
	uint8_t block[BLOCK_SIZE] = {0};
	uint8_t state[HASH_LENGTH];
	uint64_t counter;

	uint8_t old_block[BLOCK_SIZE];
	size_t old_index;

	tree->k = k;
	tree->nodes = malloc((k + 1) * sizeof (struct HashNode *));

	if (tree->nodes == NULL)
		return -1;

	tree->nodes[0] = calloc(1 << k, sizeof (struct HashNode));

	if (tree->nodes[0] == NULL) {
		destroy_diamond_structure(tree, 0);
		return -1;
	}

	/* Select initial 2^k states (the leaves of the diamond structure). */
	for (j = 0; j < (1 << k); j++)
		*(size_t *)(tree->nodes[0][j].state) = j;

	for (i = 1; i <= k; i++) {
		tree->nodes[i] = calloc(1 << (k - i), sizeof (struct HashNode));

		if (tree->nodes[i] == NULL) {
			destroy_diamond_structure(tree, i);
			return -1;
		}

		init_buckets();

		counter = 0;
		p = 0;	/* p stands for pairs. */
		j = 0;	/* points to current line for which counter block is applied. */

		/* Keep pairing nodes from previous level until all nodes are paired up.
		 * There are 2^(k-i+1) nodes on level i-1, i.e. 2^(k-i) pairs. */
		while (p < (1 << (k - i))) {
			/* Skip nodes that have already been paired up. */
			while (tree->nodes[i - 1][j].parent != NULL)
				j = (j + 1) % (1 << (k - i + 1));	/* wrap around the "lines". In i-1, there were 2^(k-i+1) lines. */

			*(uint64_t *)block = counter;
			memcpy(state, tree->nodes[i - 1][j].state, HASH_LENGTH);
			hash(state, block, BLOCK_SIZE, 0, 1);

			if (search_buckets(state, old_block, &old_index)) {
				/* Check that the colliding node has not already been paired up. */
				if (old_index != j && tree->nodes[i - 1][old_index].parent == NULL) {
					memcpy(tree->nodes[i - 1][old_index].block, old_block, BLOCK_SIZE);
					memcpy(tree->nodes[i - 1][j].block, block, BLOCK_SIZE);
					tree->nodes[i - 1][old_index].parent = &tree->nodes[i][p];
					tree->nodes[i - 1][j].parent = &tree->nodes[i][p];
					memcpy(tree->nodes[i][p].state, state, HASH_LENGTH);
					++p;
				}
			} else {
				add_to_buckets(state, block, j);
			}

			++counter;
			j = (j + 1) % (1 << (k - i + 1));	/* wrap around. */
		}
	}

	return 0;
}

void make_prediction(uint8_t predicted_hash[HASH_LENGTH], size_t prefix_blocks, const struct HashTree *tree, partial_hash_fn hash)
{
	uint8_t state[HASH_LENGTH];
	uint8_t padding_block[BLOCK_SIZE] = {0};
	uint64_t mlen;

	/* Initialize length padding block. */
	mlen = BLOCK_SIZE * (prefix_blocks + 1 + tree->k);		/* In bytes. Reserve space for prefix, linking block and suffix of k blocks. */
	padding_block[0] = 0x80;
	memcpy(padding_block + BLOCK_SIZE - 8, &mlen, 8);		/* little-endian. */

	memcpy(state, tree->nodes[tree->k][0].state, HASH_LENGTH);	/* Get final state before length padding. */
	hash(state, padding_block, BLOCK_SIZE, 0, 1);			/* Include padding block in hash. */

	memcpy(predicted_hash, state, HASH_LENGTH);
}

int produce_message(uint8_t *message, const uint8_t *prefix, size_t prefix_blocks, const struct HashTree *tree, partial_hash_fn hash)
{
	uint8_t initial_state[HASH_LENGTH];
	uint8_t link_block[BLOCK_SIZE] = {0};
	uint8_t state[HASH_LENGTH];
	uint64_t counter;
	size_t i;

	struct HashNode *node;
	uint8_t old_block[BLOCK_SIZE];
	size_t old_index;

	/* Store all leaves in the buckets. */
	init_buckets();

	for (i = 0; i < (1 << tree->k); i++)
		add_to_buckets(tree->nodes[0][i].state, tree->nodes[0][i].block, i);

	/* Find initial state after hashing prefix. */
	hash(initial_state, prefix, prefix_blocks * BLOCK_SIZE, 1, prefix_blocks);

	/* Find block linking this state into a state from the leaves of tree. */
	for (counter = 1; counter != 0; counter++) {
		memcpy(state, initial_state, HASH_LENGTH);
		*(uint64_t *)link_block = counter;
		hash(state, link_block, BLOCK_SIZE, 0, 1);

		if (search_buckets(state, old_block, &old_index))
			break;
	}

	/* Failed to find linking block. We should not reach this until the heat death of Universe... */
	if (counter == 0)
		return 1;

	memcpy(message, prefix, prefix_blocks * BLOCK_SIZE);
	memcpy(message + prefix_blocks * BLOCK_SIZE, link_block, BLOCK_SIZE);

	node = &tree->nodes[0][old_index];

	/* Follow tree to the root to append the suffix. */
	for (i = 0; i < tree->k; i++) {
		memcpy(message + (prefix_blocks + 1 + i) * BLOCK_SIZE, node->block, BLOCK_SIZE);
		node = node->parent;
	}

	return 0;
}

int main()
{
	const char *results = NULL;
	uint8_t predicted_hash[HASH_LENGTH];
	uint8_t calculated_hash[HASH_LENGTH];
	uint8_t message[(PREFIX_BLOCKS + 1 + (8 * HASH_LENGTH - 2) / 3) * BLOCK_SIZE];	/* PREFIX + LINK_BLOCK + k * SUFFIX_BLOCKS */
	struct HashTree hash_tree;
	size_t n;

	srand(time(NULL));

	n = 8 * HASH_LENGTH;

	if (build_diamond_structure(&hash_tree, (n - 2) / 3, hash_intermediate_f) != 0) {
		printf("Failed to build diamond structure.\n");
		return -1;
	}

	make_prediction(predicted_hash, PREFIX_BLOCKS, &hash_tree, hash_intermediate_f);
	printf("Predicted hash: %02x%02x%02x%02x\n", predicted_hash[0], predicted_hash[1], predicted_hash[2], predicted_hash[3]);

	results = get_results();
	print_hex(results, strlen(results) + 1);
	printf("\n\n");

	produce_message(message, results, PREFIX_BLOCKS, &hash_tree, hash_intermediate_f);
	printf("Nostradamus produced message:\n");
	print_hex(message, sizeof message);
	printf("\n");

	hash_f(calculated_hash, message, sizeof message, 1);
	printf("Calculated hash: %02x%02x%02x%02x\n", calculated_hash[0], calculated_hash[1], calculated_hash[2], calculated_hash[3]);
	printf("\n");

	if (memcmp(predicted_hash, calculated_hash, HASH_LENGTH) == 0)
		printf("Nostradamus successfully predicted the future!\n");
	else
		printf("Nostradamus failed to predict the future...\n");

	printf("hash_calls: %u\n", hash_calls);
	destroy_diamond_structure(&hash_tree, (n - 2) / 3 + 1);
	return 0;
}
