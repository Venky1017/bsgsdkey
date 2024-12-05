#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <time.h>

#define BLOOM_FILTER_SIZE 9730785280 // Adjusted size for Bloom filter
#define NUM_HASHES 10            // Number of hash functions for Bloom filter

typedef struct {
    uint8_t *bit_array;
    size_t size;
    int num_hashes;
} BloomFilter;

// Function to calculate MurmurHash3 (simple implementation for demo purposes)
uint32_t MurmurHash3_x86_32(const uint8_t *key, size_t len, uint32_t seed) {
    uint32_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x5bd1e995;
        hash ^= hash >> 15;
    }
    return hash;
}

// Bloom filter functions
BloomFilter *create_bloom_filter(size_t size, int num_hashes) {
    BloomFilter *filter = malloc(sizeof(BloomFilter));
    if (!filter) {
        perror("Failed to allocate memory for BloomFilter");
        exit(EXIT_FAILURE);
    }
    filter->bit_array = calloc((size + 7) / 8, sizeof(uint8_t));
    if (!filter->bit_array) {
        perror("Failed to allocate memory for BloomFilter bit array");
        free(filter);
        exit(EXIT_FAILURE);
    }
    filter->size = size;
    filter->num_hashes = num_hashes;
    return filter;
}

void bloom_filter_add(BloomFilter *filter, const uint8_t *data, size_t len) {
    for (int i = 0; i < filter->num_hashes; i++) {
        uint32_t hash = MurmurHash3_x86_32(data, len, i) % filter->size;
        filter->bit_array[hash / 8] |= (1 << (hash % 8));
    }
}

int bloom_filter_contains(BloomFilter *filter, const uint8_t *data, size_t len) {
    for (int i = 0; i < filter->num_hashes; i++) {
        uint32_t hash = MurmurHash3_x86_32(data, len, i) % filter->size;
        if (!(filter->bit_array[hash / 8] & (1 << (hash % 8)))) {
            return 0;
        }
    }
    return 1;
}

void bloom_filter_free(BloomFilter *filter) {
    free(filter->bit_array);
    free(filter);
}

// Utility to convert a hex string to bytes
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// RIPEMD-160 hash computation
void ripemd160_hash(const uint8_t *data, size_t len, uint8_t *out) {
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, sha256_hash);
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, out);
}

// Private key to public key conversion
void private_key_to_public_key(const uint8_t *private_key, uint8_t *public_key) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        fprintf(stderr, "Failed to create EC_KEY\n");
        exit(EXIT_FAILURE);
    }
    BIGNUM *priv_bn = BN_bin2bn(private_key, 32, NULL);
    if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn)) {
        fprintf(stderr, "Failed to set private key\n");
        exit(EXIT_FAILURE);
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL);

    EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, public_key, 33, NULL);

    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
}

// Brute force search
void brute_force_search(const uint8_t *target_hash, const uint8_t *start_key, const uint8_t *end_key, BloomFilter *bloom_filter) {
    uint8_t current_key[32];
    memcpy(current_key, start_key, 32);
    uint8_t public_key[33];
    uint8_t hash[20];

    uint64_t total_keys = 0;
    clock_t start_time = clock();

    while (memcmp(current_key, end_key, 32) <= 0) {
        private_key_to_public_key(current_key, public_key);
        ripemd160_hash(public_key, 33, hash);

        if (bloom_filter_contains(bloom_filter, hash, 20)) {
            if (memcmp(hash, target_hash, 20) == 0) {
                clock_t end_time = clock();
                double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
                printf("Found matching private key: ");
                for (int i = 0; i < 32; i++) printf("%02x", current_key[i]);
                printf("\nTime taken: %.2f seconds\n", elapsed_time);
                return;
            }
        }

        for (int i = 31; i >= 0; i--) {
            if (++current_key[i]) break;
        }
        total_keys++;
    }

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("No matching key found. Time taken: %.2f seconds. Speed: %.2f keys/s\n", elapsed_time, total_keys / elapsed_time);
}

int main() {
    // Parameters
    char *start_hex = "0000000000000000000000000000000000000000000000020000000000000000";
    char *end_hex = "000000000000000000000000000000000000000000000003ffffffffffffffff";
    char *target_hex = "20d45a6a762535700ce9e0b216e31994335db8a5";

    uint8_t start_key[32], end_key[32], target_hash[20];
    hex_to_bytes(start_hex, start_key, 32);
    hex_to_bytes(end_hex, end_key, 32);
    hex_to_bytes(target_hex, target_hash, 20);

    // Create Bloom filter
    BloomFilter *bloom_filter = create_bloom_filter(BLOOM_FILTER_SIZE, NUM_HASHES);

    // Populate Bloom filter with public key hashes
    uint8_t current_key[32];
    memcpy(current_key, start_key, 32);
    while (memcmp(current_key, end_key, 32) <= 0) {
        uint8_t public_key[33], hash[20];
        private_key_to_public_key(current_key, public_key);
        ripemd160_hash(public_key, 33, hash);
        bloom_filter_add(bloom_filter, hash, 20);

        for (int i = 31; i >= 0; i--) {
            if (++current_key[i]) break;
        }
    }

    // Search
    brute_force_search(target_hash, start_key, end_key, bloom_filter);

    bloom_filter_free(bloom_filter);
    return 0;
}
