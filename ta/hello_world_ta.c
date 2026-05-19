// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * This file implements the Secure IIoT TA command dispatcher; the filename is
 * inherited from the OP-TEE hello_world example to avoid risky build churn.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <hello_world_ta.h>

#include "paillier_ta.h"

#define AES_GCM_NONCE_LEN 12
#define AES_GCM_TAG_LEN 16
#define AAD_LEN (4 + 4 + 4 + 8)
#define STORAGE_AAD_LEN (4 + 4 + 8)
#define SECURE_IIOT_TA_VERSION "v-debug-20260516-2114"

/*
 * Prototype only. In the final design, kfog_i is provisioned by KMM and
 * stored only inside the TA/TEE. For this AES-GCM integration stage the host
 * sensor simulator uses the same demo key to produce test packets.
 */
static const uint8_t DEMO_KFOG1[16] = {
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};

/*
 * Prototype only. In the final design, kstore is provisioned by KMM and
 * sealed inside the Storage-Preparation TA. Normal World must not know
 * kstore in production.
 */
static const uint8_t DEMO_KSTORE[16] = {
	0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f
};

static void log_demo_key(const char *label, const uint8_t key[16])
{
	IMSG("%s=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	     label,
	     key[0], key[1], key[2], key[3],
	     key[4], key[5], key[6], key[7],
	     key[8], key[9], key[10], key[11],
	     key[12], key[13], key[14], key[15]);
}

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

static void build_storage_aad(uint8_t aad[STORAGE_AAD_LEN],
			      const storage_prep_input_t *input)
{
	put_u32_le(aad, input->window_id);
	put_u32_le(aad + 4, input->fog_count);
	put_u64_le(aad + 8, input->timestamp_ms);
}

static void build_storage_nonce(uint8_t nonce[AES_GCM_NONCE_LEN],
				uint32_t window_id, uint32_t fog_count)
{
	put_u32_le(nonce, window_id);
	put_u32_le(nonce + 4, fog_count);
	nonce[8] = 0xaa;
	nonce[9] = 0xbb;
	nonce[10] = 0xcc;
	nonce[11] = 0xdd;
}

static TEE_Result aes_gcm_decrypt_ta(const uint8_t *key,
				     const uint8_t *nonce,
				     size_t nonce_len,
				     const uint8_t *aad,
				     size_t aad_len,
				     const uint8_t *ciphertext,
				     size_t ciphertext_len,
				     const uint8_t *tag,
				     size_t tag_len,
				     uint8_t *plaintext,
				     size_t *plaintext_len)
{
	TEE_Result res;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr;
	size_t out_len = *plaintext_len;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key_handle);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&key_attr, TEE_ATTR_SECRET_VALUE, key, 16);
	res = TEE_PopulateTransientObject(key_handle, &key_attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&operation, TEE_ALG_AES_GCM,
				    TEE_MODE_DECRYPT, 128);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(operation, key_handle);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AEInit(operation, nonce, nonce_len, tag_len * 8,
			 aad_len, ciphertext_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (aad_len != 0)
		TEE_AEUpdateAAD(operation, aad, aad_len);

	res = TEE_AEDecryptFinal(operation, ciphertext, ciphertext_len,
				 plaintext, &out_len, (void *)tag, tag_len);
	if (res == TEE_SUCCESS)
		*plaintext_len = out_len;

out:
	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);

	return res;
}

static TEE_Result aes_gcm_encrypt_ta(const uint8_t *key,
				     const uint8_t *nonce,
				     size_t nonce_len,
				     const uint8_t *aad,
				     size_t aad_len,
				     const uint8_t *plaintext,
				     size_t plaintext_len,
				     uint8_t *ciphertext,
				     size_t *ciphertext_len,
				     uint8_t *tag,
				     size_t tag_len)
{
	TEE_Result res;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr;
	size_t out_len = *ciphertext_len;
	size_t out_tag_len = tag_len;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key_handle);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&key_attr, TEE_ATTR_SECRET_VALUE, key, 16);
	res = TEE_PopulateTransientObject(key_handle, &key_attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&operation, TEE_ALG_AES_GCM,
				    TEE_MODE_ENCRYPT, 128);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(operation, key_handle);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AEInit(operation, nonce, nonce_len, tag_len * 8,
			 aad_len, plaintext_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (aad_len != 0)
		TEE_AEUpdateAAD(operation, aad, aad_len);

	res = TEE_AEEncryptFinal(operation, plaintext, plaintext_len,
				 ciphertext, &out_len, tag, &out_tag_len);
	if (res == TEE_SUCCESS) {
		*ciphertext_len = out_len;
		if (out_tag_len != tag_len)
			res = TEE_ERROR_BAD_FORMAT;
	}

out:
	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);

	return res;
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Secure IIoT Fog Processing TA session opened");
	IMSG("Secure World demo key view (prototype only)");
	log_demo_key("  DEMO_KFOG1  ", DEMO_KFOG1);
	log_demo_key("  DEMO_KSTORE ", DEMO_KSTORE);

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Secure IIoT Fog Processing TA session closed");
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result process_sensor_packet(uint32_t param_types,
					TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	const secure_sensor_packet_t *packet;
	secure_sensor_result_t *result;
	sensor_plaintext_t plaintext;
	uint8_t aad[AAD_LEN];
	uint8_t decrypted[sizeof(sensor_plaintext_t)];
	size_t plaintext_len = sizeof(decrypted);
	TEE_Result res;

	IMSG("[DEBUG][TA] Fog param_types=0x%x expected=0x%x",
	     param_types, exp_param_types);
	IMSG("[DEBUG][TA] Fog input_size=%lu output_size=%lu expected_input_size=%lu expected_output_size=%lu paillier_max=%u",
	     (unsigned long)params[0].memref.size,
	     (unsigned long)params[1].memref.size,
	     (unsigned long)sizeof(secure_sensor_packet_t),
	     (unsigned long)sizeof(secure_sensor_result_t),
	     SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size < sizeof(*packet) ||
	    params[1].memref.size < sizeof(*result))
		return TEE_ERROR_BAD_PARAMETERS;

	packet = (const secure_sensor_packet_t *)params[0].memref.buffer;
	result = (secure_sensor_result_t *)params[1].memref.buffer;
	TEE_MemFill(result, 0, sizeof(*result));

	if (packet->plaintext_len != sizeof(sensor_plaintext_t) ||
	    packet->ciphertext_len > sizeof(packet->ciphertext) ||
	    packet->ciphertext_len != packet->plaintext_len) {
		result->status = 1;
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * AES-GCM authentication and decryption happen inside Secure World.
	 * Paillier encryption is selected at compile time so the previous mock
	 * path remains available while TA-side real encryption is validated.
	 */
	IMSG("Secure IIoT AES-GCM packet received");
	build_metadata_aad(aad, packet);
	res = aes_gcm_decrypt_ta(DEMO_KFOG1, packet->nonce,
				 AES_GCM_NONCE_LEN, aad, sizeof(aad),
				 packet->ciphertext, packet->ciphertext_len,
				 packet->tag, AES_GCM_TAG_LEN,
				 decrypted, &plaintext_len);
	if (res != TEE_SUCCESS) {
		result->status = 2;
		if (res == TEE_ERROR_MAC_INVALID)
			EMSG("AES-GCM tag verification failed");
		else
			EMSG("AES-GCM decrypt failed: 0x%x", res);
		return res;
	}

	if (plaintext_len != sizeof(plaintext)) {
		result->status = 3;
		return TEE_ERROR_BAD_FORMAT;
	}

	TEE_MemMove(&plaintext, decrypted, sizeof(plaintext));

	if (plaintext.sensor_id != packet->sensor_id ||
	    plaintext.fog_id != packet->fog_id ||
	    plaintext.window_id != packet->window_id ||
	    plaintext.timestamp_ms != packet->timestamp_ms) {
		result->status = 4;
		return TEE_ERROR_SECURITY;
	}

#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
	if (plaintext.reading_scaled < 0) {
		result->status = 5;
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = paillier_ta_encrypt_real_u32(
		(uint32_t)plaintext.reading_scaled,
		result->paillier_ciphertext, &result->paillier_ciphertext_len,
		sizeof(result->paillier_ciphertext));
	if (res == TEE_SUCCESS) {
		result->real_paillier_enabled = 1;
		result->fake_paillier_ciphertext = 0;
	}
#else
	res = paillier_ta_encrypt_mock(plaintext.sensor_id, plaintext.fog_id,
				       plaintext.window_id,
				       plaintext.reading_scaled,
				       &result->fake_paillier_ciphertext);
	if (res == TEE_SUCCESS)
		result->real_paillier_enabled = 0;
#endif
	if (res != TEE_SUCCESS) {
		result->status = 5;
		return res;
	}

	IMSG("AES-GCM verification passed");
	IMSG("Secure IIoT packet: sensor_id=%u", plaintext.sensor_id);
	IMSG("Secure IIoT packet: fog_id=%u", plaintext.fog_id);
	IMSG("Secure IIoT packet: window_id=%u", plaintext.window_id);
	IMSG("Secure IIoT decrypted reading_scaled: %d",
	     plaintext.reading_scaled);
#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
	IMSG("Real Paillier encryption inside TA completed");
	IMSG("Secure IIoT Paillier ciphertext_len=%u",
	     result->paillier_ciphertext_len);
#else
	IMSG("Mock Paillier ciphertext generated");
	IMSG("Secure IIoT fake Paillier ciphertext: %u",
	     result->fake_paillier_ciphertext);
#endif

	result->sensor_id = plaintext.sensor_id;
	result->fog_id = plaintext.fog_id;
	result->window_id = plaintext.window_id;
	result->scaled_value = (uint32_t)plaintext.reading_scaled;
	result->status = 0;
	params[1].memref.size = sizeof(*result);

	return TEE_SUCCESS;
}

static TEE_Result prepare_storage(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	const storage_prep_input_t *input;
	storage_plaintext_t plaintext;
	storage_cloud_object_t *cloud_object;
	uint8_t aad[STORAGE_AAD_LEN];
	size_t ciphertext_len;
	uint32_t plaintext_aggregate;
	TEE_Result res;

	IMSG("[DEBUG][TA] Storage param_types=0x%x expected=0x%x",
	     param_types, exp_param_types);
	IMSG("[DEBUG][TA] Storage input_size=%lu output_size=%lu expected_input_size=%lu expected_output_size=%lu paillier_max=%u",
	     (unsigned long)params[0].memref.size,
	     (unsigned long)params[1].memref.size,
	     (unsigned long)sizeof(storage_prep_input_t),
	     (unsigned long)sizeof(storage_cloud_object_t),
	     SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size < sizeof(*input) ||
	    params[1].memref.size < sizeof(*cloud_object))
		return TEE_ERROR_BAD_PARAMETERS;

	input = (const storage_prep_input_t *)params[0].memref.buffer;
	cloud_object = (storage_cloud_object_t *)params[1].memref.buffer;
	TEE_MemFill(cloud_object, 0, sizeof(*cloud_object));

	IMSG("Storage-Preparation TA received final aggregate");
	IMSG("Storage-Preparation window_id=%u", input->window_id);
	IMSG("Storage-Preparation fog_count=%u", input->fog_count);
	if (input->real_paillier_enabled == 0) {
		IMSG("Storage-Preparation fake_paillier_aggregate=%u",
		     input->fake_paillier_aggregate);
		IMSG("Storage-Preparation using mock Paillier decrypt");
		res = paillier_ta_decrypt_aggregate_mock(
			input->fake_paillier_aggregate, &plaintext_aggregate);
	} else {
		IMSG("Storage-Preparation using real Paillier decrypt inside Secure World");
		res = paillier_ta_decrypt_real_u32(
			input->paillier_aggregate,
			input->paillier_aggregate_len,
			&plaintext_aggregate);
		if (res == TEE_SUCCESS)
			IMSG("Real Paillier decrypt completed");
	}
	if (res != TEE_SUCCESS) {
		cloud_object->status = 2;
		return res;
	}

	plaintext.window_id = input->window_id;
	plaintext.plaintext_aggregate = plaintext_aggregate;
	plaintext.timestamp_ms = input->timestamp_ms;

	cloud_object->window_id = input->window_id;
	build_storage_nonce(cloud_object->nonce, input->window_id,
			    input->fog_count);
	build_storage_aad(aad, input);

	ciphertext_len = sizeof(cloud_object->ciphertext);
	res = aes_gcm_encrypt_ta(DEMO_KSTORE, cloud_object->nonce,
				 AES_GCM_NONCE_LEN, aad, sizeof(aad),
				 (const uint8_t *)&plaintext,
				 sizeof(plaintext), cloud_object->ciphertext,
				 &ciphertext_len, cloud_object->tag,
				 AES_GCM_TAG_LEN);
	if (res != TEE_SUCCESS) {
		cloud_object->status = 1;
		EMSG("AES-GCM storage encryption failed: 0x%x", res);
		return res;
	}

	cloud_object->ciphertext_len = (uint32_t)ciphertext_len;
	cloud_object->status = 0;
	params[1].memref.size = sizeof(*cloud_object);

	IMSG("AES-GCM storage encryption completed");
	IMSG("Storage-Preparation ciphertext_len=%u",
	     cloud_object->ciphertext_len);

	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	IMSG("[VERSION] Secure IIoT TA: %s", SECURE_IIOT_TA_VERSION);

	switch (cmd_id) {
	case TA_HELLO_WORLD_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_HELLO_WORLD_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_HELLO_WORLD_CMD_PROCESS_SENSOR_PACKET:
		return process_sensor_packet(param_types, params);
	case TA_HELLO_WORLD_CMD_PREPARE_STORAGE:
		return prepare_storage(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
