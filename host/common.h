// SPDX-License-Identifier: BSD-2-Clause
/*
 * Shared Normal World helpers for the Secure IIoT OP-TEE prototype.
 *
 * Real in this prototype:
 * - Sensor packet AES-GCM encryption in the Normal World sensor simulator.
 * - OP-TEE TA invocation.
 * - AES-GCM decrypt inside the Fog Processing TA.
 * - AES-GCM encrypt inside the Storage-Preparation TA.
 * - Real Paillier encryption/decryption in the prototype TA path.
 *
 * Mocked in this prototype:
 * - CP-ABE wrapping of kstore into Ck_placeholder.
 * - KMM orchestration, represented by local host flow.
 */

#ifndef SECURE_IIOT_HOST_COMMON_H
#define SECURE_IIOT_HOST_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <tee_client_api.h>

#include <hello_world_ta.h>

#define SECURE_IIOT_AES_GCM_NONCE_LEN 12
#define SECURE_IIOT_AES_GCM_TAG_LEN 16
#define SECURE_IIOT_AAD_LEN (4 + 4 + 4 + 8)
#define SECURE_IIOT_DEFAULT_BENCH_ITERS 100
#define SECURE_IIOT_WARMUP_ITERS 10

extern const sensor_plaintext_t secure_iiot_demo_readings[3];
extern const uint32_t secure_iiot_demo_reading_count;

uint64_t secure_iiot_now_us(void);
uint64_t secure_iiot_elapsed_us(uint64_t start_us, uint64_t end_us);

void secure_iiot_print_hex(const uint8_t *buf, size_t len);
void secure_iiot_print_demo_keys(void);

void secure_iiot_build_metadata_aad(uint8_t aad[SECURE_IIOT_AAD_LEN],
				    const secure_sensor_packet_t *packet);
void secure_iiot_build_demo_nonce(
	uint8_t nonce[SECURE_IIOT_AES_GCM_NONCE_LEN],
	uint32_t sensor_id, uint32_t window_id, uint32_t sequence);

int secure_iiot_create_packet(const sensor_plaintext_t *plaintext,
			      uint32_t sequence,
			      secure_sensor_packet_t *packet);

int secure_iiot_decrypt_cloud_object_for_verification(
	const storage_prep_input_t *input,
	const storage_cloud_object_t *cloud_object,
	storage_plaintext_t *out_plaintext);

TEEC_Result secure_iiot_open(TEEC_Context *ctx, TEEC_Session *sess,
			     uint32_t *err_origin);
void secure_iiot_close(TEEC_Context *ctx, TEEC_Session *sess);

TEEC_Result secure_iiot_invoke_fog_processing(
	TEEC_Session *sess, const secure_sensor_packet_t *packet,
	secure_sensor_result_t *result, uint64_t *latency_us,
	uint32_t *err_origin);

TEEC_Result secure_iiot_invoke_storage_prep(
	TEEC_Session *sess, const storage_prep_input_t *input,
	storage_cloud_object_t *cloud_object, uint64_t *latency_us,
	uint32_t *err_origin);

#endif /* SECURE_IIOT_HOST_COMMON_H */
