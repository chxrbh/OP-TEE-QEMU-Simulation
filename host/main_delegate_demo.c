// SPDX-License-Identifier: BSD-2-Clause
/*
 * Presentation demo for mocked KMM delegation and revocation.
 */

#include "common.h"
#include "kmm_mock.h"
#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SECURE_IIOT_DELEGATE_VERSION "secure_iiot_delegate_demo v-debug-20260516-2213"

static void process_sensor(TEEC_Session *sess, uint32_t sequence,
			   const sensor_plaintext_t *reading,
			   uint32_t *fog_aggregate,
			   paillier_host_keypair_t *paillier_kp,
			   BIGNUM **real_fog_aggregate,
			   int *saw_real_paillier,
			   const char *processed_text)
{
	TEEC_Result res;
	uint32_t err_origin = 0;
	secure_sensor_packet_t packet;
	secure_sensor_result_t result;
	uint64_t latency_us = 0;

	if (!secure_iiot_create_packet(reading, sequence, &packet))
		errx(1, "AES-GCM sensor packet creation failed");

	res = secure_iiot_invoke_fog_processing(sess, &packet, &result,
						&latency_us, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
		     res, err_origin);
	if (result.status != 0)
		errx(1, "Fog TA returned Secure IIoT status %u",
		     result.status);

	if (result.real_paillier_enabled) {
		char preview[33];

		*saw_real_paillier = 1;
		if (!paillier_host_add_ciphertext_bytes_real(
			    paillier_kp, real_fog_aggregate,
			    result.paillier_ciphertext,
			    result.paillier_ciphertext_len))
			errx(1, "real Paillier aggregation failed");
		paillier_host_ciphertext_preview_hex(
			result.paillier_ciphertext,
			result.paillier_ciphertext_len, 16,
			preview, sizeof(preview));
		printf("%s: real Paillier ciphertext len=%u preview=%s latency=%llu us\n",
		       processed_text, result.paillier_ciphertext_len, preview,
		       (unsigned long long)latency_us);
	} else {
		paillier_host_add_ciphertext_mock(
			fog_aggregate, result.fake_paillier_ciphertext);
		printf("%s: fake Paillier ciphertext=%u latency=%llu us\n",
		       processed_text, result.fake_paillier_ciphertext,
		       (unsigned long long)latency_us);
	}
}

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	kmm_mock_t kmm;
	uint32_t fog1_aggregate;
	uint32_t fog2_aggregate;
	uint32_t fog_aggregates[2];
	uint32_t final_aggregate;
	BIGNUM *real_fog1_aggregate = NULL;
	BIGNUM *real_fog2_aggregate = NULL;
	paillier_host_keypair_t paillier_kp = { 0 };
	int saw_real_paillier = 0;
	const uint32_t window_id = 1;
	const uint32_t overload_threshold = 80;
	sensor_plaintext_t sensor1 = {
		.sensor_id = 1,
		.fog_id = 1,
		.window_id = 1,
		.reading_scaled = 25000,
		.timestamp_ms = 1710000000001ULL,
	};
	sensor_plaintext_t sensor2_delegated = {
		.sensor_id = 1,
		.fog_id = 1,
		.window_id = 1,
		.reading_scaled = 30000,
		.timestamp_ms = 1710000000002ULL,
	};
	sensor_plaintext_t sensor3 = {
		.sensor_id = 3,
		.fog_id = 1,
		.window_id = 1,
		.reading_scaled = 18000,
		.timestamp_ms = 1710000000003ULL,
	};

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	printf("[VERSION] Host delegate demo: %s\n",
	       SECURE_IIOT_DELEGATE_VERSION);
	printf("Secure IIoT KMM Delegation/Revoke Demo\n");
	printf("[Prototype] OP-TEE QEMU demo. Fixed demo keys, 512-bit Paillier, mocked KMM/CP-ABE.\n");
	printf("[Prototype] Delegated key lifetime: one aggregation window only.\n\n");

	printf("[1] KMM setup\n");
	kmm_init(&kmm);
	if (kmm_register_fog(&kmm, 1, "A", 85) != 0 ||
	    kmm_register_fog(&kmm, 2, "B", 20) != 0 ||
	    kmm_assign_sensor(&kmm, 1, 1) != 0 ||
	    kmm_assign_sensor(&kmm, 2, 1) != 0 ||
	    kmm_assign_sensor(&kmm, 3, 1) != 0)
		errx(1, "KMM mock setup failed");
	printf("\n");

	printf("[2] Overload detection\n");
	printf("Fog A workload 85%% >= threshold %u%%\n",
	       overload_threshold);
	printf("Fog A overload trigger occurs; Fog A notifies KMM, not Fog B directly.\n");
	if (kmm_request_delegation(&kmm, 1, 1, 2, window_id) != 0)
		errx(1, "KMM delegation request failed");
	if (!kmm_verify_fog_quote(&kmm, 2))
		errx(1, "KMM mock attestation failed");
	if (kmm_authorize_delegation(&kmm, 1, 1, 2, window_id) != 0)
		errx(1, "KMM delegation authorization failed");
	if (kmm_provision_delegated_key(&kmm, 1, 2, window_id) != 0)
		errx(1, "KMM delegated key provisioning failed");
	{
		kmm_provision_input_t prov_input;
		kmm_provision_result_t prov_result;
		uint64_t provision_latency_us = 0;

		memset(&prov_input, 0, sizeof(prov_input));
		prov_input.fog_id      = 2;
		prov_input.from_fog_id = 1;
		prov_input.window_id   = window_id;
		/* Demo delegated key for Fog B scoped to Fog A's key space. */
		prov_input.key_material[0]  = 0x20; prov_input.key_material[1]  = 0x21;
		prov_input.key_material[2]  = 0x22; prov_input.key_material[3]  = 0x23;
		prov_input.key_material[4]  = 0x24; prov_input.key_material[5]  = 0x25;
		prov_input.key_material[6]  = 0x26; prov_input.key_material[7]  = 0x27;
		prov_input.key_material[8]  = 0x28; prov_input.key_material[9]  = 0x29;
		prov_input.key_material[10] = 0x2a; prov_input.key_material[11] = 0x2b;
		prov_input.key_material[12] = 0x2c; prov_input.key_material[13] = 0x2d;
		prov_input.key_material[14] = 0x2e; prov_input.key_material[15] = 0x2f;

		res = secure_iiot_invoke_provision_key(&sess, &prov_input,
						       &prov_result,
						       &provision_latency_us,
						       &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "KMM provision TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (prov_result.status != 0)
			errx(1, "KMM provision TA returned status %u",
			     prov_result.status);

		printf("[KMM] TA-side key provisioning OP-TEE round-trip: %llu us\n",
		       (unsigned long long)provision_latency_us);
	}
	printf("\n");

	printf("[3] Processing\n");
	paillier_host_init_aggregate_mock(&fog1_aggregate);
	paillier_host_init_aggregate_mock(&fog2_aggregate);
	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&real_fog1_aggregate) ||
	    !paillier_host_init_aggregate_real(&real_fog2_aggregate))
		errx(1, "real Paillier aggregate initialization failed");
	process_sensor(&sess, 1, &sensor1, &fog1_aggregate,
		       &paillier_kp, &real_fog1_aggregate, &saw_real_paillier,
		       "Sensor S1 packet under Fog A scoped key processed at Fog A TA");
	process_sensor(&sess, 2, &sensor2_delegated, &fog2_aggregate,
		       &paillier_kp, &real_fog2_aggregate, &saw_real_paillier,
		       "Sensor S1 delegated packet decrypted at Fog B TA using KMM-provisioned kfogA");
	process_sensor(&sess, 3, &sensor3, &fog1_aggregate,
		       &paillier_kp, &real_fog1_aggregate, &saw_real_paillier,
		       "Sensor S3 processed at Fog A TA");
	printf("\n");

	printf("[4] Aggregation\n");
	if (saw_real_paillier) {
		printf("Fog hosts aggregated real Paillier ciphertexts outside TA.\n");
		printf("[KMM] Combine one aggregate ciphertext per fog node\n");
		printf("[KMM] Send final aggregate to Storage-Preparation TA\n");
		printf("Real storage decrypt is covered by secure_iiot_full_crypto_demo.\n\n");
		goto revocation;
	}

	fog_aggregates[0] = fog1_aggregate;
	fog_aggregates[1] = fog2_aggregate;
	if (kmm_receive_fog_aggregate(&kmm, 1, window_id,
				      fog1_aggregate) != 0 ||
	    kmm_receive_fog_aggregate(&kmm, 2, window_id,
				      fog2_aggregate) != 0)
		errx(1, "KMM failed to receive fog aggregate");
	final_aggregate = kmm_window_combine(&kmm, window_id,
					     fog_aggregates, 2);
	printf("Fog A aggregate = %u\n", fog1_aggregate);
	printf("Fog B aggregate = %u\n", fog2_aggregate);
	printf("KMM combined Cfinal_agg = %u\n\n", final_aggregate);

	printf("[5] Storage preparation\n");
	kmm_prepare_storage(&kmm, window_id);
	{
		storage_prep_input_t storage_input = {
			.window_id = window_id,
			.fog_count = 2,
			.fake_paillier_aggregate = final_aggregate,
			.timestamp_ms = sensor3.timestamp_ms,
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

		printf("Storage-Preparation TA returned AES-GCM cloud object\n");
		printf("Cloud object ciphertext_len: %u\n",
		       cloud_object.ciphertext_len);
		printf("Storage-prep TA round-trip latency: %llu us\n\n",
		       (unsigned long long)storage_latency_us);
	}

revocation:
	printf("[6] Revocation\n");
	if (kmm_revoke_delegation(&kmm, 1, 1, 2, window_id) != 0)
		errx(1, "KMM delegation revocation failed");
	if (kmm_revoke_delegated_key(&kmm, 1, 2, window_id) != 0)
		errx(1, "KMM delegated key revocation failed");
	printf("[KMM] Delegated key lifetime: one aggregation window only.\n\n");

	printf("[7] Security note\n");
	printf("Delegation and revocation are mocked.\n");
	printf("Fog A never sends its AES key directly to Fog B.\n");
	printf("KMM is the only component that provisions the delegated fog-scoped key.\n");
	printf("Real AES-GCM processing through OP-TEE TA is still used.\n");
	printf("CP-ABE remains mocked as Ck_placeholder.\n");

	BN_free(real_fog1_aggregate);
	BN_free(real_fog2_aggregate);
	paillier_host_keypair_free(&paillier_kp);
	secure_iiot_close(&ctx, &sess);
	return 0;
}
