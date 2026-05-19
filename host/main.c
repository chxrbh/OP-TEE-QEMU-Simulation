// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID, command IDs, and shared Secure IIoT packet structs. */
#include <hello_world_ta.h>

#define AES_GCM_NONCE_LEN 12
#define AES_GCM_TAG_LEN 16
#define AAD_LEN (4 + 4 + 4 + 8)

/*
 * Prototype only. In the final design, kfog_i is provisioned by KMM and
 * stored only inside the TA/TEE. For this AES-GCM integration stage the host
 * uses the same demo key so the sensor simulator can produce test packets.
 */
static const uint8_t DEMO_KFOG1[16] = {
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};

static void put_u32_le(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static void put_u64_le(uint8_t *out, uint64_t value)
{
	uint32_t lo = (uint32_t)value;
	uint32_t hi = (uint32_t)(value >> 32);

	put_u32_le(out, lo);
	put_u32_le(out + 4, hi);
}

static void build_metadata_aad(uint8_t aad[AAD_LEN],
			       const secure_sensor_packet_t *packet)
{
	put_u32_le(aad, packet->sensor_id);
	put_u32_le(aad + 4, packet->fog_id);
	put_u32_le(aad + 8, packet->window_id);
	put_u64_le(aad + 12, packet->timestamp_ms);
}

static void build_demo_nonce(uint8_t nonce[AES_GCM_NONCE_LEN],
			     uint32_t sensor_id, uint32_t window_id,
			     uint32_t sequence)
{
	put_u32_le(nonce, sensor_id);
	put_u32_le(nonce + 4, window_id);
	put_u32_le(nonce + 8, sequence);
}

static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *plaintext, size_t plaintext_len,
			   uint8_t *ciphertext, size_t *ciphertext_len,
			   uint8_t *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len = 0;
	int out_len = 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
		goto err;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				AES_GCM_NONCE_LEN, NULL) != 1)
		goto err;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto err;
	if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto err;
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
			      (int)plaintext_len) != 1)
		goto err;

	out_len = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &len) != 1)
		goto err;
	out_len += len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
				AES_GCM_TAG_LEN, tag) != 1)
		goto err;

	*ciphertext_len = (size_t)out_len;
	EVP_CIPHER_CTX_free(ctx);
	return 1;

err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static uint64_t elapsed_us(const struct timespec *start,
			   const struct timespec *end)
{
	uint64_t start_us = (uint64_t)start->tv_sec * 1000000ULL +
			    (uint64_t)start->tv_nsec / 1000ULL;
	uint64_t end_us = (uint64_t)end->tv_sec * 1000000ULL +
			  (uint64_t)end->tv_nsec / 1000ULL;

	return end_us - start_us;
}

static void print_hex(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	uint32_t err_origin;
	uint32_t i;
	uint32_t fake_aggregate_ciphertext = 0;
	uint64_t total_latency_us = 0;
	uint64_t storage_latency_us = 0;
	const sensor_plaintext_t readings[] = {
		{ .sensor_id = 1, .fog_id = 1, .window_id = 1,
		  .reading_scaled = 25000, .timestamp_ms = 1710000000001ULL },
		{ .sensor_id = 2, .fog_id = 1, .window_id = 1,
		  .reading_scaled = 30000, .timestamp_ms = 1710000000002ULL },
		{ .sensor_id = 3, .fog_id = 1, .window_id = 1,
		  .reading_scaled = 18000, .timestamp_ms = 1710000000003ULL },
	};
	const uint32_t packet_count = sizeof(readings) / sizeof(readings[0]);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);

	printf("Secure IIoT Real AES-GCM Demo\n");

	for (i = 0; i < packet_count; i++) {
		const sensor_plaintext_t *plaintext = &readings[i];
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		uint8_t aad[AAD_LEN];
		size_t ciphertext_len = 0;
		struct timespec start;
		struct timespec end;
		uint64_t latency_us;

		memset(&packet, 0, sizeof(packet));
		memset(&result, 0, sizeof(result));
		memset(&op, 0, sizeof(op));

		packet.sensor_id = plaintext->sensor_id;
		packet.fog_id = plaintext->fog_id;
		packet.window_id = plaintext->window_id;
		packet.timestamp_ms = plaintext->timestamp_ms;
		packet.plaintext_len = sizeof(*plaintext);
		build_demo_nonce(packet.nonce, packet.sensor_id,
				 packet.window_id, i + 1);
		build_metadata_aad(aad, &packet);

		if (!aes_gcm_encrypt(DEMO_KFOG1, packet.nonce, aad, sizeof(aad),
				     (const uint8_t *)plaintext,
				     sizeof(*plaintext), packet.ciphertext,
				     &ciphertext_len, packet.tag))
			errx(1, "AES-GCM encryption failed");
		if (ciphertext_len > sizeof(packet.ciphertext))
			errx(1, "AES-GCM ciphertext does not fit demo packet");

		packet.ciphertext_len = (uint32_t)ciphertext_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = &packet;
		op.params[0].tmpref.size = sizeof(packet);
		op.params[1].tmpref.buffer = &result;
		op.params[1].tmpref.size = sizeof(result);

		printf("Sending AES-GCM packet: sensor=%u window=%u fog=%u\n",
		       packet.sensor_id, packet.window_id, packet.fog_id);
		printf("Ciphertext length: %u\n", packet.ciphertext_len);

		if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
			err(1, "clock_gettime start failed");
		res = TEEC_InvokeCommand(&sess,
					 TA_SECURE_IIOT_CMD_PROCESS_AES_PACKET,
					 &op, &err_origin);
		if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
			err(1, "clock_gettime end failed");

		latency_us = elapsed_us(&start, &end);
		total_latency_us += latency_us;

		if (res != TEEC_SUCCESS)
			errx(1,
			     "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (result.status != 0)
			errx(1, "TA returned Secure IIoT status %u",
			     result.status);

		fake_aggregate_ciphertext += result.fake_paillier_ciphertext;

		printf("TA returned fake Paillier ciphertext: %u\n",
		       result.fake_paillier_ciphertext);
		printf("TA round-trip latency: %llu us\n\n",
		       (unsigned long long)latency_us);
	}

	printf("Processed packets: %u\n", packet_count);
	printf("Fake aggregate ciphertext: %u\n", fake_aggregate_ciphertext);
	printf("Average Fog Processing TA round-trip latency: %llu us\n",
	       (unsigned long long)(total_latency_us / packet_count));
	printf("Normal World sent AES-GCM ciphertext packets; AES-GCM decrypt happened inside Secure World.\n");
	printf("Paillier is still mocked in this stage.\n\n");

	printf("Secure IIoT Storage-Preparation Demo\n");
	printf("KMM mock: combining fog aggregate for window 1\n");
	printf("Sending final fake Paillier aggregate to Storage-Preparation TA: %u\n",
	       fake_aggregate_ciphertext);

	{
		storage_prep_input_t storage_input;
		storage_cloud_object_t cloud_object;
		struct timespec start;
		struct timespec end;

		memset(&storage_input, 0, sizeof(storage_input));
		memset(&cloud_object, 0, sizeof(cloud_object));
		memset(&op, 0, sizeof(op));

		storage_input.window_id = 1;
		storage_input.fog_count = 1;
		storage_input.fake_paillier_aggregate = fake_aggregate_ciphertext;
		storage_input.timestamp_ms =
			readings[packet_count - 1].timestamp_ms;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = &storage_input;
		op.params[0].tmpref.size = sizeof(storage_input);
		op.params[1].tmpref.buffer = &cloud_object;
		op.params[1].tmpref.size = sizeof(cloud_object);

		if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
			err(1, "clock_gettime storage start failed");
		res = TEEC_InvokeCommand(&sess,
					 TA_SECURE_IIOT_CMD_PREPARE_STORAGE,
					 &op, &err_origin);
		if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
			err(1, "clock_gettime storage end failed");

		storage_latency_us = elapsed_us(&start, &end);

		if (res != TEEC_SUCCESS)
			errx(1,
			     "Storage TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (cloud_object.status != 0)
			errx(1, "Storage-Preparation TA returned status %u",
			     cloud_object.status);

		printf("Storage-Preparation TA returned AES-GCM cloud object\n");
		printf("Cloud object window_id: %u\n", cloud_object.window_id);
		printf("Cloud object ciphertext_len: %u\n",
		       cloud_object.ciphertext_len);
		printf("Cloud object nonce: ");
		print_hex(cloud_object.nonce, sizeof(cloud_object.nonce));
		printf("\n");
		printf("Cloud object tag: ");
		print_hex(cloud_object.tag, sizeof(cloud_object.tag));
		printf("\n");
		printf("Storage-prep TA round-trip latency: %llu us\n",
		       (unsigned long long)storage_latency_us);
		printf("Ck_placeholder represents CP-ABE-wrapped storage key in the prototype.\n");
		printf("Cloud stores only {Cdata, Ck_placeholder}; plaintext aggregate is not returned to Normal World.\n");
		printf("Fog Processing uses real AES-GCM decrypt. Storage Preparation uses real AES-GCM encrypt. Paillier remains mocked.\n");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
