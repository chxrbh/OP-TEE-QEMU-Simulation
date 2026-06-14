// SPDX-License-Identifier: BSD-2-Clause
/*
 * Clean timing benchmark for Secure IIoT OP-TEE calls.
 */

#include "common.h"
#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECURE_IIOT_STORAGE_BENCH_ITERS 30
#define SECURE_IIOT_PROVISION_BENCH_ITERS 30

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

static uint32_t parse_iterations(int argc, char *argv[])
{
	char *end = NULL;
	unsigned long value;

	if (argc == 1)
		return SECURE_IIOT_DEFAULT_BENCH_ITERS;
	if (argc != 2)
		errx(1, "usage: %s [measured_iterations]", argv[0]);

	value = strtoul(argv[1], &end, 10);
	if (!end || *end != '\0' || value == 0 || value > UINT32_MAX)
		errx(1, "invalid measured iteration count: %s", argv[1]);

	return (uint32_t)value;
}

static sensor_plaintext_t build_bench_reading(uint32_t iteration)
{
	sensor_plaintext_t reading = {
		.sensor_id = (iteration % 3) + 1,
		.fog_id = 1,
		.window_id = 1,
		.reading_scaled = 25000 + (int32_t)(iteration % 17),
		.timestamp_ms = 1710001000000ULL + iteration,
	};

	return reading;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	uint32_t measured_iterations = parse_iterations(argc, argv);
	uint32_t total_iterations =
		SECURE_IIOT_WARMUP_ITERS + measured_iterations;
	uint64_t *fog_latencies;
	uint64_t storage_latencies[SECURE_IIOT_STORAGE_BENCH_ITERS];
	uint64_t fog_mean;
	uint64_t fog_min;
	uint64_t fog_max;
	uint64_t fog_p50;
	uint64_t fog_p95;
	uint64_t storage_mean;
	uint64_t storage_min;
	uint64_t storage_max;
	uint64_t storage_p50;
	uint64_t storage_p95;
	uint64_t provision_latencies[SECURE_IIOT_PROVISION_BENCH_ITERS];
	uint64_t provision_mean;
	uint64_t provision_min;
	uint64_t provision_max;
	uint64_t provision_p50;
	uint64_t provision_p95;
	uint32_t fake_aggregate_ciphertext = 0;
	BIGNUM *real_aggregate_ciphertext = NULL;
	paillier_host_keypair_t paillier_kp = { 0 };
	int saw_real_paillier = 0;
	uint32_t i;
	uint32_t measured_index = 0;

	fog_latencies = calloc(measured_iterations, sizeof(*fog_latencies));
	if (!fog_latencies)
		errx(1, "failed to allocate latency arrays");

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	paillier_host_init_aggregate_mock(&fake_aggregate_ciphertext);
	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&real_aggregate_ciphertext))
		errx(1, "real Paillier aggregate initialization failed");

	for (i = 0; i < total_iterations; i++) {
		sensor_plaintext_t reading = build_bench_reading(i);
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		uint64_t latency_us = 0;

		if (!secure_iiot_create_packet(&reading, i + 1, &packet))
			errx(1, "AES-GCM sensor packet creation failed");

		res = secure_iiot_invoke_fog_processing(
			&sess, &packet, &result, &latency_us, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (result.status != 0)
			errx(1, "Fog TA returned Secure IIoT status %u",
			     result.status);

		if (i >= SECURE_IIOT_WARMUP_ITERS) {
			fog_latencies[measured_index++] = latency_us;
			if (result.real_paillier_enabled) {
				saw_real_paillier = 1;
				if (!paillier_host_add_ciphertext_bytes_real(
					    &paillier_kp,
					    &real_aggregate_ciphertext,
					    result.paillier_ciphertext,
					    result.paillier_ciphertext_len))
					errx(1,
					     "real Paillier aggregation failed");
			} else {
				paillier_host_add_ciphertext_mock(
					&fake_aggregate_ciphertext,
					result.fake_paillier_ciphertext);
			}
		}
	}

	compute_stats(fog_latencies, measured_iterations, &fog_mean, &fog_min,
		      &fog_max, &fog_p50, &fog_p95);

	memset(storage_latencies, 0, sizeof(storage_latencies));
	if (!saw_real_paillier) {
		for (i = 0; i < SECURE_IIOT_STORAGE_BENCH_ITERS; i++) {
			storage_prep_input_t storage_input = {
				.window_id = 1,
				.fog_count = 1,
				.fake_paillier_aggregate =
					fake_aggregate_ciphertext,
				.timestamp_ms =
					1710001000000ULL + total_iterations +
					i,
			};
			storage_cloud_object_t cloud_object;
			uint64_t storage_latency_us = 0;

			res = secure_iiot_invoke_storage_prep(
				&sess, &storage_input, &cloud_object,
				&storage_latency_us, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1,
				     "Storage TA InvokeCommand failed with code 0x%x origin 0x%x",
				     res, err_origin);
			if (cloud_object.status != 0)
				errx(1,
				     "Storage-Preparation TA returned status %u",
				     cloud_object.status);
			storage_latencies[i] = storage_latency_us;
		}
	}

	if (saw_real_paillier) {
		storage_mean = 0;
		storage_min = 0;
		storage_max = 0;
		storage_p50 = 0;
		storage_p95 = 0;
	} else {
		compute_stats(storage_latencies, SECURE_IIOT_STORAGE_BENCH_ITERS,
			      &storage_mean, &storage_min, &storage_max,
			      &storage_p50, &storage_p95);
	}

	/* KMM provision key benchmark: warmup then measured iterations. */
	{
		kmm_provision_input_t prov_input;
		kmm_provision_result_t prov_result;
		uint32_t prov_total = SECURE_IIOT_WARMUP_ITERS +
				      SECURE_IIOT_PROVISION_BENCH_ITERS;
		uint32_t prov_measured = 0;

		memset(&prov_input, 0, sizeof(prov_input));
		prov_input.fog_id      = 2;
		prov_input.from_fog_id = 1;
		prov_input.window_id   = 1;
		prov_input.key_material[0]  = 0x20; prov_input.key_material[1]  = 0x21;
		prov_input.key_material[2]  = 0x22; prov_input.key_material[3]  = 0x23;
		prov_input.key_material[4]  = 0x24; prov_input.key_material[5]  = 0x25;
		prov_input.key_material[6]  = 0x26; prov_input.key_material[7]  = 0x27;
		prov_input.key_material[8]  = 0x28; prov_input.key_material[9]  = 0x29;
		prov_input.key_material[10] = 0x2a; prov_input.key_material[11] = 0x2b;
		prov_input.key_material[12] = 0x2c; prov_input.key_material[13] = 0x2d;
		prov_input.key_material[14] = 0x2e; prov_input.key_material[15] = 0x2f;

		memset(provision_latencies, 0, sizeof(provision_latencies));

		for (i = 0; i < prov_total; i++) {
			uint64_t prov_latency_us = 0;

			res = secure_iiot_invoke_provision_key(
				&sess, &prov_input, &prov_result,
				&prov_latency_us, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1,
				     "Provision TA InvokeCommand failed with code 0x%x origin 0x%x",
				     res, err_origin);
			if (prov_result.status != 0)
				errx(1, "Provision TA returned status %u",
				     prov_result.status);

			if (i >= SECURE_IIOT_WARMUP_ITERS)
				provision_latencies[prov_measured++] =
					prov_latency_us;
		}
	}

	compute_stats(provision_latencies, SECURE_IIOT_PROVISION_BENCH_ITERS,
		      &provision_mean, &provision_min, &provision_max,
		      &provision_p50, &provision_p95);

	printf("Secure IIoT OP-TEE Benchmark\n");
	printf("warmup_iterations,%u\n", SECURE_IIOT_WARMUP_ITERS);
	printf("measured_iterations,%u\n", measured_iterations);
	printf("storage_iterations,%u\n", SECURE_IIOT_STORAGE_BENCH_ITERS);
	printf("provision_iterations,%u\n", SECURE_IIOT_PROVISION_BENCH_ITERS);
	printf("aes_gcm,real\n");
	printf("paillier,%s\n", saw_real_paillier ? "real_ta_encrypt" :
						 "mocked");
	printf("storage_aes_gcm,%s\n", saw_real_paillier ? "skipped" :
							  "real");
	printf("tee,optee_qemu\n\n");

	printf("metric,value_us\n");
	printf("fog_ta_mean_us,%llu\n", (unsigned long long)fog_mean);
	printf("fog_ta_min_us,%llu\n", (unsigned long long)fog_min);
	printf("fog_ta_max_us,%llu\n", (unsigned long long)fog_max);
	printf("fog_ta_p50_us,%llu\n", (unsigned long long)fog_p50);
	printf("fog_ta_p95_us,%llu\n", (unsigned long long)fog_p95);
	if (saw_real_paillier) {
		printf("storage_ta_mean_us,see_secure_iiot_full_crypto_bench\n");
	} else {
		printf("storage_ta_mean_us,%llu\n",
		       (unsigned long long)storage_mean);
		printf("storage_ta_min_us,%llu\n",
		       (unsigned long long)storage_min);
		printf("storage_ta_max_us,%llu\n",
		       (unsigned long long)storage_max);
		printf("storage_ta_p50_us,%llu\n",
		       (unsigned long long)storage_p50);
		printf("storage_ta_p95_us,%llu\n",
		       (unsigned long long)storage_p95);
	}
	printf("provision_ta_mean_us,%llu\n", (unsigned long long)provision_mean);
	printf("provision_ta_min_us,%llu\n",  (unsigned long long)provision_min);
	printf("provision_ta_max_us,%llu\n",  (unsigned long long)provision_max);
	printf("provision_ta_p50_us,%llu\n",  (unsigned long long)provision_p50);
	printf("provision_ta_p95_us,%llu\n",  (unsigned long long)provision_p95);
	printf("\n");
	if (saw_real_paillier)
		printf("Results measure OP-TEE round-trip, real AES-GCM, and TA-side real Paillier encryption. Use secure_iiot_full_crypto_bench for storage-prep real Paillier decrypt.\n");
	else
		printf("Results measure OP-TEE round-trip and real AES-GCM operations. Paillier is mocked.\n");

	secure_iiot_close(&ctx, &sess);
	BN_free(real_aggregate_ciphertext);
	paillier_host_keypair_free(&paillier_kp);
	free(fog_latencies);
	return 0;
}
