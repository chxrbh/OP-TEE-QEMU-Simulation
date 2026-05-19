// SPDX-License-Identifier: BSD-2-Clause
/*
 * Pure Normal World Paillier reference benchmark.
 *
 * This measures host-side OpenSSL BIGNUM Paillier only. It does not call
 * OP-TEE and must not be interpreted as TA performance.
 */

#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PAILLIER_BENCH_DEFAULT_BITS 512U
#define PAILLIER_BENCH_DEFAULT_ITERS 100U

static uint64_t now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		err(1, "clock_gettime failed");

	return (uint64_t)ts.tv_sec * 1000000ULL +
	       (uint64_t)ts.tv_nsec / 1000ULL;
}

static int compare_u64(const void *a, const void *b)
{
	uint64_t lhs = *(const uint64_t *)a;
	uint64_t rhs = *(const uint64_t *)b;

	if (lhs < rhs)
		return -1;
	if (lhs > rhs)
		return 1;
	return 0;
}

static uint64_t percentile(const uint64_t *sorted, size_t count,
			   unsigned int pct)
{
	size_t index;

	if (count == 0)
		return 0;

	index = ((count * pct) + 99) / 100;
	if (index == 0)
		index = 1;
	index--;
	if (index >= count)
		index = count - 1;

	return sorted[index];
}

static void compute_stats(const uint64_t *latencies, uint32_t count,
			  uint64_t *mean, uint64_t *min, uint64_t *max,
			  uint64_t *p50, uint64_t *p95)
{
	uint64_t *sorted;
	uint64_t sum = 0;
	uint32_t i;

	if (count == 0) {
		*mean = 0;
		*min = 0;
		*max = 0;
		*p50 = 0;
		*p95 = 0;
		return;
	}

	sorted = calloc(count, sizeof(*sorted));
	if (!sorted)
		errx(1, "failed to allocate sorted latency array");

	*min = UINT64_MAX;
	*max = 0;
	for (i = 0; i < count; i++) {
		uint64_t value = latencies[i];

		sum += value;
		if (value < *min)
			*min = value;
		if (value > *max)
			*max = value;
		sorted[i] = value;
	}

	qsort(sorted, count, sizeof(*sorted), compare_u64);
	*mean = sum / count;
	*p50 = percentile(sorted, count, 50);
	*p95 = percentile(sorted, count, 95);

	free(sorted);
}

static uint32_t parse_u32_arg(const char *arg, const char *name)
{
	char *end = NULL;
	unsigned long value;

	value = strtoul(arg, &end, 10);
	if (!end || *end != '\0' || value == 0 || value > UINT32_MAX)
		errx(1, "invalid %s: %s", name, arg);

	return (uint32_t)value;
}

static void parse_args(int argc, char *argv[], uint32_t *bits,
		       uint32_t *iterations)
{
	if (argc == 1) {
		*bits = PAILLIER_BENCH_DEFAULT_BITS;
		*iterations = PAILLIER_BENCH_DEFAULT_ITERS;
		return;
	}
	if (argc != 3)
		errx(1, "usage: %s [key_bits iterations]", argv[0]);

	*bits = parse_u32_arg(argv[1], "key size");
	*iterations = parse_u32_arg(argv[2], "iteration count");
	if (*bits < 32)
		errx(1, "key size must be at least 32 bits");
}

int main(int argc, char *argv[])
{
	paillier_host_keypair_t kp = { 0 };
	BIGNUM **ciphertexts = NULL;
	BIGNUM *aggregate = NULL;
	BIGNUM *next_aggregate = NULL;
	uint64_t *encrypt_latencies = NULL;
	uint64_t *add_latencies = NULL;
	uint64_t keygen_us;
	uint64_t decrypt_us;
	uint64_t start_us;
	uint64_t end_us;
	uint64_t encrypt_mean;
	uint64_t encrypt_min;
	uint64_t encrypt_max;
	uint64_t encrypt_p50;
	uint64_t encrypt_p95;
	uint64_t add_mean;
	uint64_t add_min;
	uint64_t add_max;
	uint64_t add_p50;
	uint64_t add_p95;
	uint32_t bits;
	uint32_t iterations;
	uint32_t decrypted = 0;
	uint32_t i;

	parse_args(argc, argv, &bits, &iterations);

	ciphertexts = calloc(iterations, sizeof(*ciphertexts));
	encrypt_latencies = calloc(iterations, sizeof(*encrypt_latencies));
	add_latencies = calloc(iterations > 1 ? iterations - 1 : 1,
			       sizeof(*add_latencies));
	if (!ciphertexts || !encrypt_latencies || !add_latencies)
		errx(1, "failed to allocate benchmark arrays");

	start_us = now_us();
	if (!paillier_host_keygen_demo(&kp, (int)bits))
		errx(1, "Paillier key generation failed");
	end_us = now_us();
	keygen_us = end_us - start_us;

	for (i = 0; i < iterations; i++) {
		uint32_t reading = 25000U + (i % 100U);

		start_us = now_us();
		if (!paillier_host_encrypt_u32(&kp, reading, &ciphertexts[i]))
			errx(1, "Paillier encryption failed");
		end_us = now_us();
		encrypt_latencies[i] = end_us - start_us;
	}

	aggregate = BN_dup(ciphertexts[0]);
	if (!aggregate)
		errx(1, "failed to duplicate initial ciphertext");

	for (i = 1; i < iterations; i++) {
		start_us = now_us();
		if (!paillier_host_add_ciphertexts_real(&kp, aggregate,
							ciphertexts[i],
							&next_aggregate))
			errx(1, "Paillier homomorphic addition failed");
		end_us = now_us();
		add_latencies[i - 1] = end_us - start_us;
		BN_free(aggregate);
		aggregate = next_aggregate;
		next_aggregate = NULL;
	}

	start_us = now_us();
	if (!paillier_host_decrypt_u32(&kp, aggregate, &decrypted))
		errx(1, "Paillier decryption failed");
	end_us = now_us();
	decrypt_us = end_us - start_us;

	compute_stats(encrypt_latencies, iterations, &encrypt_mean,
		      &encrypt_min, &encrypt_max, &encrypt_p50, &encrypt_p95);
	compute_stats(add_latencies, iterations > 1 ? iterations - 1 : 0,
		      &add_mean, &add_min, &add_max, &add_p50, &add_p95);

	printf("Secure IIoT Paillier Host Reference Benchmark\n");
	printf("[Benchmark] Paillier key size: %u-bit\n", bits);
	printf("[Benchmark] Paillier ciphertext size: %d bytes\n",
	       BN_num_bytes(kp.n2));
	printf("[Benchmark] Host-side reference only; no OP-TEE TA timing.\n");
	if (bits == 512)
		printf("[Prototype] 512-bit Paillier is for fast functional demo only.\n");
	if (bits == 2048)
		printf("[Benchmark] 2048-bit Paillier is used for paper-aligned benchmark.\n");
	printf("key_bits,%u\n", bits);
	printf("paillier_key_bits,%u\n", bits);
	printf("paillier_ciphertext_len,%d\n", BN_num_bytes(kp.n2));
	printf("iterations,%u\n\n", iterations);
	printf("metric,value_us\n");
	printf("keygen_us,%llu\n", (unsigned long long)keygen_us);
	printf("encrypt_mean_us,%llu\n", (unsigned long long)encrypt_mean);
	printf("encrypt_min_us,%llu\n", (unsigned long long)encrypt_min);
	printf("encrypt_max_us,%llu\n", (unsigned long long)encrypt_max);
	printf("encrypt_p50_us,%llu\n", (unsigned long long)encrypt_p50);
	printf("encrypt_p95_us,%llu\n", (unsigned long long)encrypt_p95);
	printf("add_mean_us,%llu\n", (unsigned long long)add_mean);
	printf("decrypt_us,%llu\n", (unsigned long long)decrypt_us);
	printf("ciphertext_bytes,%d\n", BN_num_bytes(kp.n2));
	printf("\n");
	printf("This benchmark measures host-side real Paillier reference performance. TA Paillier integration is future work.\n");

	for (i = 0; i < iterations; i++)
		BN_free(ciphertexts[i]);
	BN_free(aggregate);
	free(ciphertexts);
	free(encrypt_latencies);
	free(add_latencies);
	paillier_host_keypair_free(&kp);

	return 0;
}
