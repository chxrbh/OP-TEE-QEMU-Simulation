// SPDX-License-Identifier: BSD-2-Clause
/*
 * Human-readable Secure IIoT OP-TEE presentation demo.
 */

#include "common.h"
#include "kmm_mock.h"
#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	uint32_t i;
	uint32_t fog_aggregate = 0;
	BIGNUM *real_fog_aggregate = NULL;
	uint32_t final_aggregate;
	int saw_real_paillier = 0;
	paillier_host_keypair_t paillier_kp = { 0 };
	kmm_mock_t kmm;

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	printf("Secure IIoT OP-TEE Presentation Demo\n\n");
	secure_iiot_print_demo_keys();

	printf("[1] KMM setup\n");
	kmm_init(&kmm);
	if (kmm_register_fog(&kmm, 1, "F1", 40) != 0 ||
	    kmm_register_fog(&kmm, 2, "F2", 20) != 0 ||
	    kmm_assign_sensor(&kmm, 1, 1) != 0 ||
	    kmm_assign_sensor(&kmm, 2, 1) != 0 ||
	    kmm_assign_sensor(&kmm, 3, 1) != 0)
		errx(1, "KMM mock setup failed");
	printf("\n");

	printf("[2] Sensor-side AES-GCM encryption and Fog Processing TA\n");
	paillier_host_init_aggregate_mock(&fog_aggregate);
	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&real_fog_aggregate))
		errx(1, "real Paillier aggregate initialization failed");
	for (i = 0; i < secure_iiot_demo_reading_count; i++) {
		const sensor_plaintext_t *plaintext =
			&secure_iiot_demo_readings[i];
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		uint64_t latency_us = 0;

		if (!secure_iiot_create_packet(plaintext, i + 1, &packet))
			errx(1, "AES-GCM sensor packet creation failed");

		printf("Sensor %u sends AES-GCM ciphertext packet to Fog F%u\n",
		       packet.sensor_id, packet.fog_id);

		res = secure_iiot_invoke_fog_processing(
			&sess, &packet, &result, &latency_us, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (result.status != 0)
			errx(1, "Fog TA returned Secure IIoT status %u",
			     result.status);

		if (result.real_paillier_enabled) {
			char preview[33];

			saw_real_paillier = 1;
			if (!paillier_host_add_ciphertext_bytes_real(
				    &paillier_kp, &real_fog_aggregate,
				    result.paillier_ciphertext,
				    result.paillier_ciphertext_len))
				errx(1, "real Paillier aggregation failed");
			paillier_host_ciphertext_preview_hex(
				result.paillier_ciphertext,
				result.paillier_ciphertext_len, 16,
				preview, sizeof(preview));
			printf("Fog Processing TA returned real Paillier ciphertext, len=%u bytes\n",
			       result.paillier_ciphertext_len);
			printf("Ciphertext preview: %s\n", preview);
		} else {
			paillier_host_add_ciphertext_mock(
				&fog_aggregate,
				result.fake_paillier_ciphertext);
			printf("Fog Processing TA returned fake Paillier ciphertext: %u\n",
			       result.fake_paillier_ciphertext);
		}
		printf("Fog Processing TA round-trip latency: %llu us\n",
		       (unsigned long long)latency_us);
	}
	printf("\n");

	printf("[3] Fog aggregation\n");
	if (saw_real_paillier)
		printf("Fog host aggregated Paillier ciphertext outside TA.\n\n");
	else
		printf("Fog F1 aggregate Cagg,F1 = %u\n\n", fog_aggregate);

	printf("[4] KMM window combine\n");
	if (saw_real_paillier) {
		printf("KMM real Paillier aggregation path uses ciphertext multiplication outside TA.\n\n");
		printf("[5] Storage preparation\n");
		printf("Real storage-preparation decrypt is covered by secure_iiot_full_crypto_demo.\n");
		printf("This compatibility demo keeps its original mock storage branch.\n\n");
		goto security_statement;
	}

	if (kmm_receive_fog_aggregate(&kmm, 1, 1, fog_aggregate) != 0)
		errx(1, "KMM failed to receive fog aggregate");
	final_aggregate = kmm_combine_fake_aggregates(&fog_aggregate, 1);
	printf("KMM computed Cfinal_agg = %u\n\n", final_aggregate);

	printf("[5] Storage preparation\n");
	printf("KMM sends Cfinal_agg to Storage-Preparation TA\n");

	{
		storage_prep_input_t storage_input = {
			.window_id = 1,
			.fog_count = 1,
			.fake_paillier_aggregate = final_aggregate,
			.timestamp_ms =
				secure_iiot_demo_readings[
					secure_iiot_demo_reading_count - 1]
					.timestamp_ms,
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
			errx(1, "Storage-Preparation TA returned status %u",
			     cloud_object.status);

		printf("Storage-Preparation TA returned AES-GCM cloud object.\n");
		printf("Cloud object ciphertext_len: %u\n",
		       cloud_object.ciphertext_len);
		printf("Cloud object nonce: ");
		secure_iiot_print_hex(cloud_object.nonce,
				      sizeof(cloud_object.nonce));
		printf("\n");
		printf("Cloud object tag: ");
		secure_iiot_print_hex(cloud_object.tag,
				      sizeof(cloud_object.tag));
		printf("\n");
		printf("Storage-prep TA round-trip latency: %llu us\n",
		       (unsigned long long)storage_latency_us);
		printf("Ck_placeholder represents CP-ABE-wrapped storage key in the prototype.\n");
		printf("Cloud stores {Cdata, Ck_placeholder}\n\n");
	}

security_statement:
	printf("[6] Security statement\n");
	printf("Normal World sends AES-GCM ciphertext packets only.\n");
	printf("Fog Processing TA performs AES-GCM decrypt inside Secure World.\n");
	printf("Fog Host and KMM see only Paillier-like ciphertexts.\n");
	if (saw_real_paillier) {
		printf("Storage-Preparation real Paillier decrypt is available in secure_iiot_full_crypto_demo.\n");
	} else {
		printf("Storage-Preparation TA performs final AES-GCM encryption inside Secure World.\n");
		printf("Cloud stores only {Cdata, Ck_placeholder}.\n");
	}
	printf("CP-ABE, attestation, and key provisioning remain mocked/not implemented.\n");

	BN_free(real_fog_aggregate);
	paillier_host_keypair_free(&paillier_kp);
	secure_iiot_close(&ctx, &sess);
	return 0;
}
