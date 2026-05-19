// SPDX-License-Identifier: BSD-2-Clause
/*
 * Shared Normal World helpers for the Secure IIoT OP-TEE prototype.
 */

#include "common.h"

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

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

/*
 * Prototype verification only. In the final design, kstore is sealed inside
 * the Storage-Preparation TA and must not be available to Normal World.
 */
static const uint8_t DEMO_KSTORE[16] = {
	0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f
};

const sensor_plaintext_t secure_iiot_demo_readings[3] = {
	{ .sensor_id = 1, .fog_id = 1, .window_id = 1,
	  .reading_scaled = 25000, .timestamp_ms = 1710000000001ULL },
	{ .sensor_id = 2, .fog_id = 1, .window_id = 1,
	  .reading_scaled = 30000, .timestamp_ms = 1710000000002ULL },
	{ .sensor_id = 3, .fog_id = 1, .window_id = 1,
	  .reading_scaled = 18000, .timestamp_ms = 1710000000003ULL },
};

const uint32_t secure_iiot_demo_reading_count =
	sizeof(secure_iiot_demo_readings) /
	sizeof(secure_iiot_demo_readings[0]);

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
				SECURE_IIOT_AES_GCM_NONCE_LEN, NULL) != 1)
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
				SECURE_IIOT_AES_GCM_TAG_LEN, tag) != 1)
		goto err;

	*ciphertext_len = (size_t)out_len;
	EVP_CIPHER_CTX_free(ctx);
	return 1;

err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static int aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ciphertext, size_t ciphertext_len,
			   const uint8_t *tag, uint8_t *plaintext,
			   size_t *plaintext_len)
{
	EVP_CIPHER_CTX *ctx;
	int len = 0;
	int out_len = 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
		goto err;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				SECURE_IIOT_AES_GCM_NONCE_LEN, NULL) != 1)
		goto err;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto err;
	if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto err;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
			      (int)ciphertext_len) != 1)
		goto err;
	out_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
				SECURE_IIOT_AES_GCM_TAG_LEN,
				(void *)tag) != 1)
		goto err;
	if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &len) != 1)
		goto err;
	out_len += len;

	*plaintext_len = (size_t)out_len;
	EVP_CIPHER_CTX_free(ctx);
	return 1;

err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

uint64_t secure_iiot_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		err(1, "clock_gettime failed");

	return (uint64_t)ts.tv_sec * 1000000ULL +
	       (uint64_t)ts.tv_nsec / 1000ULL;
}

uint64_t secure_iiot_elapsed_us(uint64_t start_us, uint64_t end_us)
{
	return end_us - start_us;
}

void secure_iiot_print_hex(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
}

void secure_iiot_print_demo_keys(void)
{
	printf("Normal World demo key view (prototype only)\n");
	printf("  DEMO_KFOG1  = ");
	secure_iiot_print_hex(DEMO_KFOG1, sizeof(DEMO_KFOG1));
	printf("\n");
	printf("  DEMO_KSTORE = ");
	secure_iiot_print_hex(DEMO_KSTORE, sizeof(DEMO_KSTORE));
	printf("\n\n");
}

void secure_iiot_build_metadata_aad(uint8_t aad[SECURE_IIOT_AAD_LEN],
				    const secure_sensor_packet_t *packet)
{
	put_u32_le(aad, packet->sensor_id);
	put_u32_le(aad + 4, packet->fog_id);
	put_u32_le(aad + 8, packet->window_id);
	put_u64_le(aad + 12, packet->timestamp_ms);
}

static void secure_iiot_build_storage_aad(
	uint8_t aad[4 + 4 + 8], const storage_prep_input_t *input)
{
	put_u32_le(aad, input->window_id);
	put_u32_le(aad + 4, input->fog_count);
	put_u64_le(aad + 8, input->timestamp_ms);
}

void secure_iiot_build_demo_nonce(
	uint8_t nonce[SECURE_IIOT_AES_GCM_NONCE_LEN],
	uint32_t sensor_id, uint32_t window_id, uint32_t sequence)
{
	put_u32_le(nonce, sensor_id);
	put_u32_le(nonce + 4, window_id);
	put_u32_le(nonce + 8, sequence);
}

int secure_iiot_create_packet(const sensor_plaintext_t *plaintext,
			      uint32_t sequence,
			      secure_sensor_packet_t *packet)
{
	uint8_t aad[SECURE_IIOT_AAD_LEN];
	size_t ciphertext_len = 0;

	memset(packet, 0, sizeof(*packet));
	packet->sensor_id = plaintext->sensor_id;
	packet->fog_id = plaintext->fog_id;
	packet->window_id = plaintext->window_id;
	packet->timestamp_ms = plaintext->timestamp_ms;
	packet->plaintext_len = sizeof(*plaintext);

	secure_iiot_build_demo_nonce(packet->nonce, packet->sensor_id,
				     packet->window_id, sequence);
	secure_iiot_build_metadata_aad(aad, packet);

	if (!aes_gcm_encrypt(DEMO_KFOG1, packet->nonce, aad, sizeof(aad),
			     (const uint8_t *)plaintext, sizeof(*plaintext),
			     packet->ciphertext, &ciphertext_len, packet->tag))
		return 0;
	if (ciphertext_len > sizeof(packet->ciphertext))
		return 0;

	packet->ciphertext_len = (uint32_t)ciphertext_len;
	return 1;
}

int secure_iiot_decrypt_cloud_object_for_verification(
	const storage_prep_input_t *input,
	const storage_cloud_object_t *cloud_object,
	storage_plaintext_t *out_plaintext)
{
	uint8_t aad[4 + 4 + 8];
	uint8_t plaintext[sizeof(*out_plaintext)];
	size_t plaintext_len = sizeof(plaintext);

	if (!input || !cloud_object || !out_plaintext ||
	    cloud_object->ciphertext_len > sizeof(cloud_object->ciphertext))
		return 0;

	secure_iiot_build_storage_aad(aad, input);
	if (!aes_gcm_decrypt(DEMO_KSTORE, cloud_object->nonce, aad,
			     sizeof(aad), cloud_object->ciphertext,
			     cloud_object->ciphertext_len, cloud_object->tag,
			     plaintext, &plaintext_len))
		return 0;
	if (plaintext_len != sizeof(*out_plaintext))
		return 0;

	memcpy(out_plaintext, plaintext, sizeof(*out_plaintext));
	return 1;
}

TEEC_Result secure_iiot_open(TEEC_Context *ctx, TEEC_Session *sess,
			     uint32_t *err_origin)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;

	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		return res;

	res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, err_origin);
	if (res != TEEC_SUCCESS)
		TEEC_FinalizeContext(ctx);

	return res;
}

void secure_iiot_close(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_CloseSession(sess);
	TEEC_FinalizeContext(ctx);
}

TEEC_Result secure_iiot_invoke_fog_processing(
	TEEC_Session *sess, const secure_sensor_packet_t *packet,
	secure_sensor_result_t *result, uint64_t *latency_us,
	uint32_t *err_origin)
{
	TEEC_Operation op;
	uint64_t start_us;
	uint64_t end_us;
	TEEC_Result res;

	memset(result, 0, sizeof(*result));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)packet;
	op.params[0].tmpref.size = sizeof(*packet);
	op.params[1].tmpref.buffer = result;
	op.params[1].tmpref.size = sizeof(*result);

	printf("[DEBUG][HOST] Fog Invoke cmd=%u paramTypes=0x%x\n",
	       TA_SECURE_IIOT_CMD_PROCESS_AES_PACKET, op.paramTypes);
	printf("[DEBUG][HOST] Fog input_size=%zu output_size=%zu expected_output_size=%zu paillier_max=%u\n",
	       op.params[0].tmpref.size, op.params[1].tmpref.size,
	       sizeof(*result), SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX);

	start_us = secure_iiot_now_us();
	res = TEEC_InvokeCommand(sess, TA_SECURE_IIOT_CMD_PROCESS_AES_PACKET,
				 &op, err_origin);
	end_us = secure_iiot_now_us();

	if (latency_us)
		*latency_us = secure_iiot_elapsed_us(start_us, end_us);

	return res;
}

TEEC_Result secure_iiot_invoke_storage_prep(
	TEEC_Session *sess, const storage_prep_input_t *input,
	storage_cloud_object_t *cloud_object, uint64_t *latency_us,
	uint32_t *err_origin)
{
	TEEC_Operation op;
	uint64_t start_us;
	uint64_t end_us;
	TEEC_Result res;

	memset(cloud_object, 0, sizeof(*cloud_object));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)input;
	op.params[0].tmpref.size = sizeof(*input);
	op.params[1].tmpref.buffer = cloud_object;
	op.params[1].tmpref.size = sizeof(*cloud_object);

	printf("[DEBUG][HOST] Storage Invoke cmd=%u paramTypes=0x%x\n",
	       TA_SECURE_IIOT_CMD_PREPARE_STORAGE, op.paramTypes);
	printf("[DEBUG][HOST] Storage input_size=%zu output_size=%zu expected_output_size=%zu paillier_max=%u\n",
	       op.params[0].tmpref.size, op.params[1].tmpref.size,
	       sizeof(*cloud_object), SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX);

	start_us = secure_iiot_now_us();
	res = TEEC_InvokeCommand(sess, TA_SECURE_IIOT_CMD_PREPARE_STORAGE,
				 &op, err_origin);
	end_us = secure_iiot_now_us();

	if (latency_us)
		*latency_us = secure_iiot_elapsed_us(start_us, end_us);

	return res;
}
