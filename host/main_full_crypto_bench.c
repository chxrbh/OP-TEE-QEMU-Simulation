// SPDX-License-Identifier: BSD-2-Clause
/*
 * Full real crypto benchmark:
 * - Fog TA: AES-GCM decrypt + real Paillier encrypt.
 * - Host: Paillier ciphertext aggregation.
 * - Storage TA: real Paillier decrypt + AES-GCM encrypt.
 */

#include "common.h"
#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FULL_CRYPTO_WARMUP_ITERS 3U
#define FULL_CRYPTO_DEFAULT_ITERS 30U
#define SECURE_IIOT_BENCH_VERSION "secure_iiot_full_crypto_bench v-debug-20260516-2213"

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
			  uint64_t *mean, uint64_t *p50, uint64_t *p95)
{
	uint64_t *sorted;
	uint64_t sum = 0;
	uint32_t i;

	sorted = calloc(count, sizeof(*sorted));
	if (!sorted)
		errx(1, "failed to allocate sorted latency array");

	for (i = 0; i < count; i++) {
		sum += latencies[i];
		sorted[i] = latencies[i];
	}
	qsort(sorted, count, sizeof(*sorted), compare_u64);
	*mean = sum / count;
	*p50 = percentile(sorted, count, 50);
	*p95 = percentile(sorted, count, 95);
	free(sorted);
}

static uint32_t paillier_ciphertext_len_for_bits(uint32_t key_bits)
{
	return (key_bits * 2U + 7U) / 8U;
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

static void parse_args(int argc, char *argv[], uint32_t *iterations,
		       uint32_t *key_bits)
{
	if (argc == 1) {
		*iterations = FULL_CRYPTO_DEFAULT_ITERS;
		*key_bits = SECURE_IIOT_PAILLIER_DEMO_KEY_BITS;
		return;
	}
	if (argc == 2) {
		*iterations = parse_u32_arg(argv[1], "measured iteration count");
		*key_bits = SECURE_IIOT_PAILLIER_DEMO_KEY_BITS;
		return;
	}
	if (argc != 3)
		errx(1, "usage: %s [measured_iterations [512|2048]]", argv[0]);

	*iterations = parse_u32_arg(argv[1], "measured iteration count");
	*key_bits = parse_u32_arg(argv[2], "Paillier key size");
	if (*key_bits != SECURE_IIOT_PAILLIER_DEMO_KEY_BITS &&
	    *key_bits != SECURE_IIOT_PAILLIER_2048_KEY_BITS)
		errx(1, "supported Paillier key sizes are 512 and 2048");
}

static void print_benchmark_header(uint32_t measured_iterations,
				   uint32_t key_bits,
				   uint32_t ciphertext_len,
				   const char *mode)
{
	printf("[VERSION] Host benchmark: %s\n", SECURE_IIOT_BENCH_VERSION);
	printf("Secure IIoT Full Crypto Benchmark\n");
	printf("[Benchmark] Paillier key size: %u-bit\n", key_bits);
	printf("[Benchmark] Paillier ciphertext size: %u bytes\n",
	       ciphertext_len);
	printf("[Benchmark] OP-TEE QEMU timing only; not physical hardware timing\n");
	printf("[Benchmark] First TA call may be slower due to TA loading; warm-up iterations=%u\n",
	       FULL_CRYPTO_WARMUP_ITERS);
	if (key_bits == SECURE_IIOT_PAILLIER_DEMO_KEY_BITS)
		printf("[Prototype] 512-bit Paillier is for fast functional demo only.\n");
	if (key_bits == SECURE_IIOT_PAILLIER_2048_KEY_BITS) {
		printf("[Benchmark] 2048-bit Paillier is used for paper-aligned host reference benchmark.\n");
		printf("[Limitation] TA-side 2048-bit Paillier is not enabled in this QEMU prototype; this mode does not silently fall back to the 512-bit TA key.\n");
	}
	printf("mode,%s\n", mode);
	printf("iterations,%u\n", measured_iterations);
	printf("paillier_key_bits,%u\n", key_bits);
	printf("paillier_ciphertext_len,%u\n\n", ciphertext_len);
}

static int run_host_reference_2048(uint32_t measured_iterations)
{
	uint32_t total_iterations = FULL_CRYPTO_WARMUP_ITERS +
				    measured_iterations;
	uint64_t *fog_latencies;
	uint64_t *host_aggregate_latencies;
	uint64_t *storage_latencies;
	uint64_t fog_mean;
	uint64_t fog_p50;
	uint64_t fog_p95;
	uint64_t host_mean;
	uint64_t host_p50;
	uint64_t host_p95;
	uint64_t storage_mean;
	uint64_t storage_p50;
	uint64_t storage_p95;
	paillier_host_keypair_t paillier_kp = { 0 };
	uint32_t iteration;
	uint32_t fog_index = 0;
	uint32_t pipeline_index = 0;

	fog_latencies = calloc(measured_iterations *
			       secure_iiot_demo_reading_count,
			       sizeof(*fog_latencies));
	host_aggregate_latencies = calloc(measured_iterations,
					  sizeof(*host_aggregate_latencies));
	storage_latencies = calloc(measured_iterations,
				   sizeof(*storage_latencies));
	if (!fog_latencies || !host_aggregate_latencies || !storage_latencies)
		errx(1, "failed to allocate latency arrays");

	if (!paillier_host_keygen_demo(&paillier_kp,
				       SECURE_IIOT_PAILLIER_2048_KEY_BITS))
		errx(1, "2048-bit host Paillier key generation failed");

	for (iteration = 0; iteration < total_iterations; iteration++) {
		BIGNUM *ciphertexts[3] = { 0 };
		BIGNUM *aggregate = NULL;
		uint64_t start_us;
		uint64_t end_us;
		uint32_t decrypted = 0;
		uint32_t i;
		int measured = iteration >= FULL_CRYPTO_WARMUP_ITERS;

		for (i = 0; i < secure_iiot_demo_reading_count; i++) {
			sensor_plaintext_t reading =
				secure_iiot_demo_readings[i];
			secure_sensor_packet_t packet;

			reading.timestamp_ms += iteration * 1000ULL;
			if (!secure_iiot_create_packet(
				    &reading,
				    iteration * secure_iiot_demo_reading_count +
					    i + 1,
				    &packet))
				errx(1, "AES-GCM sensor packet creation failed");

			start_us = secure_iiot_now_us();
			if (!paillier_host_encrypt_u32(
				    &paillier_kp,
				    (uint32_t)reading.reading_scaled,
				    &ciphertexts[i]))
				errx(1, "2048-bit host Paillier encryption failed");
			end_us = secure_iiot_now_us();
			if (measured)
				fog_latencies[fog_index++] =
					secure_iiot_elapsed_us(start_us,
							       end_us);
		}

		start_us = secure_iiot_now_us();
		if (!paillier_host_init_aggregate_real(&aggregate))
			errx(1, "real Paillier aggregate initialization failed");
		for (i = 0; i < secure_iiot_demo_reading_count; i++) {
			BIGNUM *next = NULL;

			if (!paillier_host_add_ciphertexts_real(
				    &paillier_kp, aggregate, ciphertexts[i],
				    &next))
				errx(1, "2048-bit host Paillier aggregation failed");
			BN_free(aggregate);
			aggregate = next;
		}
		end_us = secure_iiot_now_us();
		if (measured)
			host_aggregate_latencies[pipeline_index] =
				secure_iiot_elapsed_us(start_us, end_us);

		start_us = secure_iiot_now_us();
		if (!paillier_host_decrypt_u32(&paillier_kp, aggregate,
					       &decrypted))
			errx(1, "2048-bit host Paillier decrypt failed");
		end_us = secure_iiot_now_us();
		if (measured) {
			storage_latencies[pipeline_index] =
				secure_iiot_elapsed_us(start_us, end_us);
			pipeline_index++;
		}

		for (i = 0; i < secure_iiot_demo_reading_count; i++)
			BN_free(ciphertexts[i]);
		BN_free(aggregate);
	}

	compute_stats(fog_latencies,
		      measured_iterations * secure_iiot_demo_reading_count,
		      &fog_mean, &fog_p50, &fog_p95);
	compute_stats(host_aggregate_latencies, measured_iterations,
		      &host_mean, &host_p50, &host_p95);
	compute_stats(storage_latencies, measured_iterations,
		      &storage_mean, &storage_p50, &storage_p95);

	print_benchmark_header(measured_iterations,
			       SECURE_IIOT_PAILLIER_2048_KEY_BITS,
			       paillier_ciphertext_len_for_bits(
				       SECURE_IIOT_PAILLIER_2048_KEY_BITS),
			       "host_reference_2048_no_ta");
	printf("metric,value_us\n");
	printf("fog_ta_mean_us,%llu\n", (unsigned long long)fog_mean);
	printf("fog_ta_p50_us,%llu\n", (unsigned long long)fog_p50);
	printf("fog_ta_p95_us,%llu\n", (unsigned long long)fog_p95);
	printf("host_aggregate_mean_us,%llu\n",
	       (unsigned long long)host_mean);
	printf("host_aggregate_p50_us,%llu\n",
	       (unsigned long long)host_p50);
	printf("host_aggregate_p95_us,%llu\n",
	       (unsigned long long)host_p95);
	printf("storage_ta_mean_us,%llu\n",
	       (unsigned long long)storage_mean);
	printf("storage_ta_p50_us,%llu\n",
	       (unsigned long long)storage_p50);
	printf("storage_ta_p95_us,%llu\n",
	       (unsigned long long)storage_p95);
	printf("paillier_key_bits,%u\n", SECURE_IIOT_PAILLIER_2048_KEY_BITS);
	printf("paillier_ciphertext_len,%u\n",
	       paillier_ciphertext_len_for_bits(
		       SECURE_IIOT_PAILLIER_2048_KEY_BITS));

	paillier_host_keypair_free(&paillier_kp);
	free(fog_latencies);
	free(host_aggregate_latencies);
	free(storage_latencies);
	return 0;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	uint32_t measured_iterations;
	uint32_t key_bits;
	uint32_t total_iterations;
	uint64_t *fog_latencies;
	uint64_t *host_aggregate_latencies;
	uint64_t *storage_latencies;
	uint64_t fog_mean;
	uint64_t fog_p50;
	uint64_t fog_p95;
	uint64_t host_mean;
	uint64_t host_p50;
	uint64_t host_p95;
	uint64_t storage_mean;
	uint64_t storage_p50;
	uint64_t storage_p95;
	paillier_host_keypair_t paillier_kp = { 0 };
	uint32_t aggregate_len = SECURE_IIOT_PAILLIER_DEMO_CIPHERTEXT_LEN;
	uint32_t iteration;
	uint32_t fog_index = 0;
	uint32_t pipeline_index = 0;

	parse_args(argc, argv, &measured_iterations, &key_bits);
	if (key_bits == SECURE_IIOT_PAILLIER_2048_KEY_BITS)
		return run_host_reference_2048(measured_iterations);
	total_iterations = FULL_CRYPTO_WARMUP_ITERS + measured_iterations;

	fog_latencies = calloc(measured_iterations *
			       secure_iiot_demo_reading_count,
			       sizeof(*fog_latencies));
	host_aggregate_latencies = calloc(measured_iterations,
					  sizeof(*host_aggregate_latencies));
	storage_latencies = calloc(measured_iterations,
				   sizeof(*storage_latencies));
	if (!fog_latencies || !host_aggregate_latencies || !storage_latencies)
		errx(1, "failed to allocate latency arrays");

	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	for (iteration = 0; iteration < total_iterations; iteration++) {
		secure_sensor_result_t results[3];
		BIGNUM *aggregate = NULL;
		uint8_t aggregate_bytes[SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX];
		storage_prep_input_t storage_input;
		storage_cloud_object_t cloud_object;
		uint64_t start_us;
		uint64_t end_us;
		uint64_t storage_latency_us = 0;
		uint32_t i;
		int measured = iteration >= FULL_CRYPTO_WARMUP_ITERS;

		for (i = 0; i < secure_iiot_demo_reading_count; i++) {
			secure_sensor_packet_t packet;
			uint64_t fog_latency_us = 0;
			sensor_plaintext_t reading =
				secure_iiot_demo_readings[i];

			reading.timestamp_ms += iteration * 1000ULL;
			if (!secure_iiot_create_packet(
				    &reading,
				    iteration * secure_iiot_demo_reading_count +
					    i + 1,
				    &packet))
				errx(1, "AES-GCM sensor packet creation failed");
			res = secure_iiot_invoke_fog_processing(
				&sess, &packet, &results[i], &fog_latency_us,
				&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1,
				     "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
				     res, err_origin);
			if (results[i].status != 0)
				errx(1, "Fog TA returned Secure IIoT status %u",
				     results[i].status);
			if (!results[i].real_paillier_enabled)
				errx(1, "TA did not return real Paillier ciphertext");
			if (measured)
				fog_latencies[fog_index++] = fog_latency_us;
		}

		start_us = secure_iiot_now_us();
		if (!paillier_host_init_aggregate_real(&aggregate))
			errx(1, "real Paillier aggregate initialization failed");
		for (i = 0; i < secure_iiot_demo_reading_count; i++) {
			if (!paillier_host_add_ciphertext_bytes_real(
				    &paillier_kp, &aggregate,
				    results[i].paillier_ciphertext,
				    results[i].paillier_ciphertext_len))
				errx(1, "real Paillier aggregation failed");
		}
		if (!paillier_host_bn_to_fixed_bytes(aggregate,
						     aggregate_bytes,
						     aggregate_len))
			errx(1, "failed to serialize aggregate ciphertext");
		end_us = secure_iiot_now_us();
		if (measured)
			host_aggregate_latencies[pipeline_index] =
				secure_iiot_elapsed_us(start_us, end_us);

		memset(&storage_input, 0, sizeof(storage_input));
		storage_input.window_id = 1;
		storage_input.fog_count = 1;
		memcpy(storage_input.paillier_aggregate, aggregate_bytes,
		       aggregate_len);
		storage_input.paillier_aggregate_len = aggregate_len;
		storage_input.real_paillier_enabled = 1;
		storage_input.timestamp_ms = 1710000000999ULL + iteration;

		res = secure_iiot_invoke_storage_prep(
			&sess, &storage_input, &cloud_object,
			&storage_latency_us, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "Storage TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (cloud_object.status != 0)
			errx(1, "Storage-Preparation TA returned status %u",
			     cloud_object.status);
		if (measured) {
			storage_latencies[pipeline_index] =
				storage_latency_us;
			pipeline_index++;
		}

		BN_free(aggregate);
	}

	compute_stats(fog_latencies,
		      measured_iterations * secure_iiot_demo_reading_count,
		      &fog_mean, &fog_p50, &fog_p95);
	compute_stats(host_aggregate_latencies, measured_iterations,
		      &host_mean, &host_p50, &host_p95);
	compute_stats(storage_latencies, measured_iterations,
		      &storage_mean, &storage_p50, &storage_p95);

	print_benchmark_header(measured_iterations,
			       SECURE_IIOT_PAILLIER_DEMO_KEY_BITS,
			       aggregate_len, "optee_qemu_ta_512");
	printf("aes_gcm,real\n");
	printf("paillier_encrypt_ta,real\n");
	printf("paillier_aggregate_host,real\n");
	printf("paillier_decrypt_storage_ta,real\n");
	printf("storage_aes_gcm,real\n");
	printf("tee,optee_qemu\n");
	printf("prototype_key_warning,512-bit-not-production\n\n");
	printf("metric,value_us\n");
	printf("fog_ta_mean_us,%llu\n", (unsigned long long)fog_mean);
	printf("fog_ta_p50_us,%llu\n", (unsigned long long)fog_p50);
	printf("fog_ta_p95_us,%llu\n", (unsigned long long)fog_p95);
	printf("host_aggregate_mean_us,%llu\n",
	       (unsigned long long)host_mean);
	printf("host_aggregate_p50_us,%llu\n",
	       (unsigned long long)host_p50);
	printf("host_aggregate_p95_us,%llu\n",
	       (unsigned long long)host_p95);
	printf("storage_ta_mean_us,%llu\n",
	       (unsigned long long)storage_mean);
	printf("storage_ta_p50_us,%llu\n",
	       (unsigned long long)storage_p50);
	printf("storage_ta_p95_us,%llu\n",
	       (unsigned long long)storage_p95);
	printf("paillier_key_bits,%u\n", SECURE_IIOT_PAILLIER_DEMO_KEY_BITS);
	printf("paillier_ciphertext_len,%u\n", aggregate_len);

	secure_iiot_close(&ctx, &sess);
	paillier_host_keypair_free(&paillier_kp);
	free(fog_latencies);
	free(host_aggregate_latencies);
	free(storage_latencies);
	return 0;
}
