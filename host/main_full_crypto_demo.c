// SPDX-License-Identifier: BSD-2-Clause
/*
 * Full real-crypto presentation path.
 *
 * This demo intentionally does not decrypt the returned cloud object in
 * Normal World. The aggregate is decrypted from Paillier and re-encrypted with
 * AES-GCM only inside Secure World.
 */

#include "common.h"
#include "paillier_host.h"

#include <err.h>
#include <stdio.h>
#include <string.h>

#define SECURE_IIOT_DEMO_VERSION "secure_iiot_full_crypto_demo v-debug-20260516-2213"

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
	storage_prep_input_t storage_input;
	storage_cloud_object_t cloud_object;
	uint32_t i;

	printf("[VERSION] Host demo: %s\n", SECURE_IIOT_DEMO_VERSION);
	printf("Secure IIoT Full Crypto Pipeline Demo\n");
	printf("[Prototype] OP-TEE QEMU demo. Fixed demo keys, 512-bit Paillier, mocked KMM/CP-ABE.\n");
	printf("[Prototype] 512-bit Paillier is for fast functional demo only.\n\n");
	secure_iiot_print_demo_keys();

	if (!paillier_host_init_fixed_demo_key(&paillier_kp))
		errx(1, "fixed demo Paillier key initialization failed");
	if (!paillier_host_init_aggregate_real(&aggregate))
		errx(1, "real Paillier aggregate initialization failed");

	res = secure_iiot_open(&ctx, &sess, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC session setup failed with code 0x%x origin 0x%x",
		     res, err_origin);

	printf("[1] Sensor simulator creates AES-GCM packets in Normal World\n");
	for (i = 0; i < secure_iiot_demo_reading_count; i++) {
		secure_sensor_packet_t packet;
		secure_sensor_result_t result;
		const sensor_plaintext_t *reading =
			&secure_iiot_demo_readings[i];

		if (!secure_iiot_create_packet(reading, i + 1, &packet))
			errx(1, "AES-GCM sensor packet creation failed");

		printf("  Sensor S%u -> AES-GCM ciphertext packet, window W=%u\n",
		       reading->sensor_id, reading->window_id);
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
			errx(1, "TA did not return real Paillier ciphertext");
		if (result.paillier_ciphertext_len != aggregate_len)
			errx(1, "unexpected Paillier ciphertext len=%u",
			     result.paillier_ciphertext_len);

		if (!paillier_host_add_ciphertext_bytes_real(
			    &paillier_kp, &aggregate,
			    result.paillier_ciphertext,
			    result.paillier_ciphertext_len))
			errx(1, "real Paillier aggregation failed");

		printf("  Fog TA authenticated/decrypted inside Secure World and returned only Paillier ciphertext len=%u bytes\n",
		       result.paillier_ciphertext_len);
	}

	printf("\n[2] Fog Host aggregates Paillier ciphertext outside TA\n");
	printf("  Normal World sees ciphertexts only; no plaintext sensor readings are returned.\n\n");

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

	printf("[3] KMM mock forwards final aggregate ciphertext\n");
	printf("  [KMM] Send final aggregate to Storage-Preparation TA\n\n");
	printf("[4] Storage-Preparation TA\n");
	printf("  Decrypts Paillier aggregate inside Secure World.\n");
	printf("  Re-encrypts final aggregate into AES-GCM cloud object inside Secure World.\n");
	res = secure_iiot_invoke_storage_prep(
		&sess, &storage_input, &cloud_object, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1,
		     "Storage TA InvokeCommand failed with code 0x%x origin 0x%x",
		     res, err_origin);
	if (cloud_object.status != 0)
		errx(1, "Storage-Preparation TA returned status %u",
		     cloud_object.status);

	printf("  Cloud object Cdata ciphertext_len: %u\n",
	       cloud_object.ciphertext_len);
	printf("  Cdata nonce: ");
	secure_iiot_print_hex(cloud_object.nonce, sizeof(cloud_object.nonce));
	printf("\n  Cdata tag: ");
	secure_iiot_print_hex(cloud_object.tag, sizeof(cloud_object.tag));
	printf("\n  Ck_placeholder represents CP-ABE-wrapped storage key in the prototype.\n");
	printf("  Cloud stores only {Cdata, Ck_placeholder}.\n");
	printf("\n[Security invariant] Plaintext aggregate is not returned to Normal World in this full crypto path.\n");

	secure_iiot_close(&ctx, &sess);
	BN_free(aggregate);
	paillier_host_keypair_free(&paillier_kp);
	return 0;
}
