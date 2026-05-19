// SPDX-License-Identifier: BSD-2-Clause
/*
 * Pure Normal World Paillier reference test.
 *
 * This does not call OP-TEE. It validates real host-side Paillier math and
 * fixed-width ciphertext serialization before any future TA integration.
 */

#include "paillier_host.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PAILLIER_REF_KEY_BITS 512
#define PAILLIER_REF_READING_COUNT 3
#define PAILLIER_REF_EXPECTED_AGGREGATE 73000U

int main(void)
{
	const uint32_t readings[PAILLIER_REF_READING_COUNT] = {
		25000, 30000, 18000
	};
	paillier_host_keypair_t kp = { 0 };
	BIGNUM *ciphertexts[PAILLIER_REF_READING_COUNT] = { NULL };
	BIGNUM *aggregate = NULL;
	BIGNUM *next_aggregate = NULL;
	uint8_t *serialized = NULL;
	BIGNUM *roundtrip = NULL;
	uint32_t decrypted = 0;
	size_t ciphertext_bytes;
	size_t i;
	int pass = 0;

	printf("Secure IIoT Real Paillier Reference Test\n");
	printf("Paillier key size: 512-bit prototype key\n");
	printf("Encrypting readings: 25000, 30000, 18000\n");
	printf("Homomorphic add: Cagg = C1 * C2 * C3 mod n^2\n");

	if (!paillier_host_keygen_demo(&kp, PAILLIER_REF_KEY_BITS))
		errx(1, "Paillier key generation failed");

	ciphertext_bytes = (size_t)BN_num_bytes(kp.n2);
	serialized = calloc(ciphertext_bytes, sizeof(*serialized));
	if (!serialized)
		errx(1, "failed to allocate ciphertext serialization buffer");

	for (i = 0; i < PAILLIER_REF_READING_COUNT; i++) {
		if (!paillier_host_encrypt_u32(&kp, readings[i],
					       &ciphertexts[i]))
			errx(1, "Paillier encryption failed");
	}

	aggregate = BN_dup(ciphertexts[0]);
	if (!aggregate)
		errx(1, "failed to duplicate initial ciphertext");

	for (i = 1; i < PAILLIER_REF_READING_COUNT; i++) {
		if (!paillier_host_add_ciphertexts_real(&kp, aggregate,
							ciphertexts[i],
							&next_aggregate))
			errx(1, "Paillier homomorphic addition failed");
		BN_free(aggregate);
		aggregate = next_aggregate;
		next_aggregate = NULL;
	}

	if (!paillier_host_bn_to_fixed_bytes(aggregate, serialized,
					     ciphertext_bytes))
		errx(1, "Paillier fixed-width serialization failed");
	if (!paillier_host_fixed_bytes_to_bn(serialized, ciphertext_bytes,
					     &roundtrip))
		errx(1, "Paillier fixed-width parse failed");
	if (BN_cmp(aggregate, roundtrip) != 0)
		errx(1, "Paillier fixed-width serialization roundtrip failed");

	if (!paillier_host_decrypt_u32(&kp, aggregate, &decrypted))
		errx(1, "Paillier decryption failed");

	pass = decrypted == PAILLIER_REF_EXPECTED_AGGREGATE;
	printf("Ciphertext byte length: %zu\n", ciphertext_bytes);
	printf("Decrypted aggregate: %u\n", decrypted);
	printf("Expected aggregate: %u\n", PAILLIER_REF_EXPECTED_AGGREGATE);
	printf("Result: %s\n", pass ? "PASS" : "FAIL");

	for (i = 0; i < PAILLIER_REF_READING_COUNT; i++)
		BN_free(ciphertexts[i]);
	BN_free(aggregate);
	BN_free(roundtrip);
	free(serialized);
	paillier_host_keypair_free(&kp);

	return pass ? 0 : 1;
}
