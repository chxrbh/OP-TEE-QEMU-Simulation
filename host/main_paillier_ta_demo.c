// SPDX-License-Identifier: BSD-2-Clause
/*
 * Dedicated demo for TA-side real Paillier encryption.
 *
 * This verifies the current architecture slice:
 * - AES-GCM decrypt happens inside Fog Processing TA.
 * - Paillier encryption happens inside Fog Processing TA.
 * - Paillier aggregation happens outside TA in Normal World.
 * - Paillier decrypt is performed by this host reference only for prototype
 *   correctness testing. Final architecture moves skP to Storage-Preparation
 *   TA and does not keep it in Normal World.
 */

#include "common.h"
#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>

#define EXPECTED_AGGREGATE 73000U

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t err_origin = 0;
	paillier_host_keypair_t paillier_kp = { 0 };
	BIGNUM *aggregate = NULL;
	uint32_t decrypted_aggregate = 0;
	uint32_t i;
	int pass = 0;

	printf("Secure IIoT TA Real Paillier Encryption Demo\n");
	printf("AES-GCM decrypt: real inside TA\n");
	printf("Paillier encrypt: real inside TA\n");
	printf("Paillier aggregate: real outside TA\n");
	printf("Paillier decrypt: real in Storage-Preparation TA path\n\n");
	printf("Prototype note: this uses a fixed 512-bit Paillier key. Production target is 2048-bit or stronger.\n");
	printf("Host private key is used only for reference verification in this demo.\n\n");

	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&aggregate))
		errx(1, "real Paillier aggregate initialization failed");

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	for (i = 0; i < secure_iiot_demo_reading_count; i++) {
		const sensor_plaintext_t *plaintext =
			&secure_iiot_demo_readings[i];
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		char preview[33];

		printf("Sending packet sensor=%u reading_scaled=%d\n",
		       plaintext->sensor_id, plaintext->reading_scaled);

		if (!secure_iiot_create_packet(plaintext, i + 1, &packet))
			errx(1, "AES-GCM sensor packet creation failed");

		res = secure_iiot_invoke_fog_processing(
			&sess, &packet, &result, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "Fog TA InvokeCommand failed with code 0x%x origin 0x%x",
			     res, err_origin);
		if (result.status != 0)
			errx(1, "Fog TA returned Secure IIoT status %u",
			     result.status);
		if (!result.real_paillier_enabled)
			errx(1, "Fog TA returned mock Paillier path");
		if (result.paillier_ciphertext_len !=
		    SECURE_IIOT_PAILLIER_DEMO_CIPHERTEXT_LEN)
			errx(1, "unexpected Paillier ciphertext length %u",
			     result.paillier_ciphertext_len);

		if (!paillier_host_add_ciphertext_bytes_real(
			    &paillier_kp, &aggregate,
			    result.paillier_ciphertext,
			    result.paillier_ciphertext_len))
			errx(1, "Fog host real Paillier aggregation failed");

		paillier_host_ciphertext_preview_hex(
			result.paillier_ciphertext,
			result.paillier_ciphertext_len, 16,
			preview, sizeof(preview));
		printf("TA returned Paillier ciphertext len=%u bytes\n",
		       result.paillier_ciphertext_len);
		printf("Ciphertext preview: %s\n\n", preview);
	}

	printf("Fog host aggregated real Paillier ciphertext outside TA.\n");
	printf("Storage-preparation real Paillier decrypt is exercised by secure_iiot_full_crypto_demo.\n\n");

	if (!paillier_host_decrypt_u32(&paillier_kp, aggregate,
				       &decrypted_aggregate))
		errx(1, "host reference Paillier decrypt failed");

	pass = decrypted_aggregate == EXPECTED_AGGREGATE;
	printf("Host reference decrypted aggregate: %u\n", decrypted_aggregate);
	printf("Expected aggregate: %u\n", EXPECTED_AGGREGATE);
	printf("Verification: %s\n", pass ? "PASS" : "FAIL");
	printf("Result: %s if all TA encryptions succeeded.\n",
	       pass ? "PASS" : "FAIL");

	secure_iiot_close(&ctx, &sess);
	BN_free(aggregate);
	paillier_host_keypair_free(&paillier_kp);
	return pass ? 0 : 1;
}
