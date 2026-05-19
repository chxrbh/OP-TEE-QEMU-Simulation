// SPDX-License-Identifier: BSD-2-Clause
/*
 * Secure World Paillier placeholder API.
 *
 * Real Paillier encrypt/decrypt will later replace these functions. The TA
 * keeps this boundary so AES-GCM processing stays stable while the mock is
 * isolated behind a clean module.
 */

#ifndef SECURE_IIOT_PAILLIER_TA_H
#define SECURE_IIOT_PAILLIER_TA_H

#include <stdint.h>

#include <tee_internal_api.h>

#ifndef SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
#define SECURE_IIOT_ENABLE_REAL_PAILLIER_TA 1
#endif

TEE_Result paillier_ta_encrypt_mock(uint32_t sensor_id, uint32_t fog_id,
				    uint32_t window_id,
				    int32_t reading_scaled,
				    uint32_t *out_fake_ciphertext);

TEE_Result paillier_ta_encrypt_real_u32(uint32_t m,
					uint8_t *out_ciphertext,
					uint32_t *out_len,
					uint32_t out_max_len);

TEE_Result paillier_ta_decrypt_real_u32(const uint8_t *ciphertext,
					uint32_t ciphertext_len,
					uint32_t *out_m);

TEE_Result paillier_ta_decrypt_aggregate_mock(
	uint32_t fake_paillier_aggregate,
	uint32_t *out_plaintext_aggregate);

#endif /* SECURE_IIOT_PAILLIER_TA_H */
