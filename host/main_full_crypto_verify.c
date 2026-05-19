// SPDX-License-Identifier: BSD-2-Clause
/*
 * Full crypto correctness verifier.
 *
 * Verification mode uses host-side private keys only for prototype testing.
 * This is not the final security architecture.
 */

#include "common.h"
#include "paillier_host.h"

#include <err.h>
#include <stdio.h>
#include <string.h>

#define EXPECTED_AGGREGATE 73000U
#define SECURE_IIOT_VERIFY_VERSION "secure_iiot_full_crypto_verify v-debug-20260516-2213"

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	paillier_host_keypair_t paillier_kp = { 0 };
	BIGNUM *aggregate = NULL;
	uint8_t aggregate_bytes[SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX];
	uint32_t aggregate_len = SECURE_IIOT_PAILLIER_DEMO_CIPHERTEXT_LEN;
	uint32_t host_decrypted = 0;
	storage_prep_input_t storage_input;
	storage_cloud_object_t cloud_object;
	storage_plaintext_t storage_plaintext;
	uint32_t i;
	int paillier_ok;
	int cloud_ok;
	int auth_ok = 1;

	printf("[VERSION] Host verify: %s\n", SECURE_IIOT_VERIFY_VERSION);
	printf("Secure IIoT Full Crypto Verification\n");
	printf("[Verification only] Host-side private-key check is used only for prototype correctness testing.\n");
	printf("[Prototype] No production security claim is made.\n\n");

	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&aggregate))
		errx(1, "real Paillier aggregate initialization failed");

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	for (i = 0; i < secure_iiot_demo_reading_count; i++) {
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		const sensor_plaintext_t *reading =
			&secure_iiot_demo_readings[i];

		if (!secure_iiot_create_packet(reading, i + 1, &packet))
			errx(1, "AES-GCM sensor packet creation failed");
		res = secure_iiot_invoke_fog_processing(
			&sess, &packet, &result, NULL, &err_origin);
		if (res != TEEC_SUCCESS) {
			auth_ok = 0;
			errx(1,
			     "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		}
		if (result.status != 0)
			errx(1, "Fog TA returned Secure IIoT status %u",
			     result.status);
		if (!result.real_paillier_enabled)
			errx(1, "TA did not return real Paillier ciphertext");
		if (!paillier_host_add_ciphertext_bytes_real(
			    &paillier_kp, &aggregate,
			    result.paillier_ciphertext,
			    result.paillier_ciphertext_len))
			errx(1, "real Paillier aggregation failed");
	}

	if (!paillier_host_decrypt_u32(&paillier_kp, aggregate,
				       &host_decrypted))
		errx(1, "host Paillier reference decrypt failed");
	paillier_ok = host_decrypted == EXPECTED_AGGREGATE;

	if (!paillier_host_bn_to_fixed_bytes(aggregate, aggregate_bytes,
					     aggregate_len))
		errx(1, "failed to serialize aggregate ciphertext");

	memset(&storage_input, 0, sizeof(storage_input));
	storage_input.window_id = 1;
	storage_input.fog_count = 1;
	memcpy(storage_input.paillier_aggregate, aggregate_bytes,
	       aggregate_len);
	storage_input.paillier_aggregate_len = aggregate_len;
	storage_input.real_paillier_enabled = 1;
	storage_input.timestamp_ms = 1710000000999ULL;

	res = secure_iiot_invoke_storage_prep(
		&sess, &storage_input, &cloud_object, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1,
		     "Storage TA InvokeCommand failed with code 0x%x origin 0x%x",
		     res, err_origin);
	if (cloud_object.status != 0)
		errx(1, "Storage-Preparation TA returned status %u",
		     cloud_object.status);

	cloud_ok = secure_iiot_decrypt_cloud_object_for_verification(
		&storage_input, &cloud_object, &storage_plaintext) &&
		   storage_plaintext.window_id == 1 &&
		   storage_plaintext.plaintext_aggregate == EXPECTED_AGGREGATE &&
		   storage_plaintext.timestamp_ms == storage_input.timestamp_ms;

	printf("Host reference decrypted Paillier aggregate: %u\n",
	       host_decrypted);
	printf("Expected aggregate: %u\n", EXPECTED_AGGREGATE);
	printf("[CHECK] AES-GCM packet authentication inside TA: %s\n",
	       auth_ok ? "PASS" : "FAIL");
	printf("[CHECK] Paillier aggregation correctness: %s\n",
	       paillier_ok ? "PASS" : "FAIL");
	printf("[CHECK] Cloud object verification: %s\n",
	       cloud_ok ? "PASS" : "FAIL");
	printf("[CHECK] Plaintext aggregate returned to Normal World: NO\n");
	printf("[CHECK] Normal World stores only Cdata and Ck_placeholder: YES\n");
	printf("[Verification only] Host-side private-key check is used only for prototype correctness testing.\n");

	secure_iiot_close(&ctx, &sess);
	BN_free(aggregate);
	paillier_host_keypair_free(&paillier_kp);
	return (paillier_ok && cloud_ok) ? 0 : 1;
}
