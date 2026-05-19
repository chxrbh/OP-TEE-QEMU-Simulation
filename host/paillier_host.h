// SPDX-License-Identifier: BSD-2-Clause
/*
 * Host-side Paillier APIs.
 *
 * The *_mock functions are the existing prototype path used by the OP-TEE
 * demos. They intentionally model Paillier-like aggregation with simple
 * integer addition.
 *
 * The BIGNUM APIs are a Normal World reference implementation for validating
 * real Paillier math and fixed-width serialization before any future TA port.
 */

#ifndef SECURE_IIOT_PAILLIER_HOST_H
#define SECURE_IIOT_PAILLIER_HOST_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/bn.h>

typedef struct {
	BIGNUM *n;
	BIGNUM *n2;
	BIGNUM *g;
	BIGNUM *lambda;
	BIGNUM *mu;
	BN_CTX *ctx;
} paillier_host_keypair_t;

void paillier_host_init_aggregate_mock(uint32_t *aggregate);

void paillier_host_add_ciphertext_mock(uint32_t *aggregate,
				       uint32_t fake_ciphertext);

uint32_t paillier_host_combine_aggregates_mock(const uint32_t *aggregates,
					       uint32_t count);

int paillier_host_keygen_demo(paillier_host_keypair_t *kp, int bits);

int paillier_host_init_fixed_demo_key(paillier_host_keypair_t *kp);

void paillier_host_keypair_free(paillier_host_keypair_t *kp);

int paillier_host_encrypt_u32(const paillier_host_keypair_t *kp,
			      uint32_t m, BIGNUM **out_c);

int paillier_host_add_ciphertexts_real(const paillier_host_keypair_t *kp,
				       const BIGNUM *c1,
				       const BIGNUM *c2,
				       BIGNUM **out_c);

int paillier_host_init_aggregate_real(BIGNUM **out_aggregate);

int paillier_host_add_ciphertext_bytes_real(
	const paillier_host_keypair_t *kp, BIGNUM **aggregate,
	const uint8_t *ciphertext, size_t ciphertext_len);

int paillier_host_decrypt_u32(const paillier_host_keypair_t *kp,
			      const BIGNUM *c, uint32_t *out_m);

int paillier_host_bn_to_fixed_bytes(const BIGNUM *bn, uint8_t *out,
				    size_t out_len);

int paillier_host_fixed_bytes_to_bn(const uint8_t *in, size_t in_len,
				    BIGNUM **out_bn);

void paillier_host_ciphertext_preview_hex(const uint8_t *ciphertext,
					  size_t ciphertext_len,
					  size_t preview_len,
					  char *out_hex,
					  size_t out_hex_len);

#endif /* SECURE_IIOT_PAILLIER_HOST_H */
