// SPDX-License-Identifier: BSD-2-Clause
/*
 * Secure World Paillier operations.
 *
 * The mock path is kept as a compile-time fallback for presentation demos.
 * The real encrypt/decrypt path uses fixed 512-bit Paillier demo key material
 * and LibTomMath. This is prototype-only; production should use 2048-bit or
 * stronger keys provisioned by KMM and protected by the final key lifecycle.
 */

#include "paillier_ta.h"

#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
#include <tommath.h>
#endif

#define PAILLIER_TA_CIPHERTEXT_BYTES 128
#define PAILLIER_TA_RANDOM_BYTES 64
#define PAILLIER_TA_RANDOM_ATTEMPTS 16

#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
/*
 * Fixed demo Paillier key material.
 *
 * Insecure and deterministic for prototype repeatability only. In the final
 * design, KMM provisions/seals skP only to the Storage-Preparation TA. The
 * Normal Fog Processing TA should not have skP in production. In this single-TA
 * prototype, both encrypt and storage-prep commands exist in one TA for
 * demonstration simplicity.
 */
static const char PAILLIER_N_HEX[] =
	"d2007a47121b1ea33ba8c1cc20b9011fff3aff9c15c830773b1b55de7c21b20f"
	"7a42be8d4dfc2a4eebc351acdbeb5e6b69c4fa1e537e1c8cb26352ee3dd4a38d";
static const char PAILLIER_G_HEX[] =
	"d2007a47121b1ea33ba8c1cc20b9011fff3aff9c15c830773b1b55de7c21b20f"
	"7a42be8d4dfc2a4eebc351acdbeb5e6b69c4fa1e537e1c8cb26352ee3dd4a38e";
static const char PAILLIER_N2_HEX[] =
	"ac44c89cd41c4f40b3674489447e8f2d2450afbeac4bb3408f9b33554acf6f3"
	"d4bf5e1261b42598d1453d5613312c9da3a496683aac2559ff20c2650723d463"
	"204a8ed0c62eb260facea94541ffe827d6d14a706c91e87e5201bf79456f7946"
	"97ba0e91aee73e572b979c064ecdd362158df90611e42bd71d22374bc7c04dba9";
static const char PAILLIER_LAMBDA_HEX[] =
	"34801e91c486c7a8ceea3073082e4047ffcebfe705720c1dcec6d5779f086c83"
	"6a9d232f8da0b3f2060783d5ceacf5ecfe46401553f5d21d68087aea791755c8";
static const char PAILLIER_MU_HEX[] =
	"9f4b9e3df00eacdbb148539d636842e9013deabcd55523378d87ba50ef8c0c70"
	"46b80127fcccdfed10fc793aeeae5a307792fb03b14bbe139963287be0a392aa";

static TEE_Result mp_err_to_tee(mp_err err)
{
	return err == MP_OKAY ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result read_fixed_public_key(mp_int *n, mp_int *g, mp_int *n2)
{
	mp_err err;

	err = mp_read_radix(n, PAILLIER_N_HEX, 16);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);
	err = mp_read_radix(g, PAILLIER_G_HEX, 16);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);
	err = mp_read_radix(n2, PAILLIER_N2_HEX, 16);
	return mp_err_to_tee(err);
}

static TEE_Result read_fixed_private_key(mp_int *n, mp_int *g, mp_int *n2,
					 mp_int *lambda, mp_int *mu)
{
	TEE_Result res;
	mp_err err;

	res = read_fixed_public_key(n, g, n2);
	if (res != TEE_SUCCESS)
		return res;
	err = mp_read_radix(lambda, PAILLIER_LAMBDA_HEX, 16);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);
	err = mp_read_radix(mu, PAILLIER_MU_HEX, 16);
	return mp_err_to_tee(err);
}

static TEE_Result generate_coprime_r(const mp_int *n, mp_int *r)
{
	uint8_t random_bytes[PAILLIER_TA_RANDOM_BYTES];
	mp_int gcd;
	mp_err err;
	uint32_t attempt;

	err = mp_init(&gcd);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);

	for (attempt = 0; attempt < PAILLIER_TA_RANDOM_ATTEMPTS; attempt++) {
		TEE_GenerateRandom(random_bytes, sizeof(random_bytes));

		err = mp_from_ubin(r, random_bytes, sizeof(random_bytes));
		if (err != MP_OKAY)
			goto out;
		err = mp_mod(r, n, r);
		if (err != MP_OKAY)
			goto out;
		if (mp_cmp_d(r, 0) == MP_EQ)
			continue;

		err = mp_gcd(r, n, &gcd);
		if (err != MP_OKAY)
			goto out;
		if (mp_cmp_d(&gcd, 1) == MP_EQ) {
			mp_clear(&gcd);
			return TEE_SUCCESS;
		}
	}

	err = MP_VAL;

out:
	mp_clear(&gcd);
	return mp_err_to_tee(err);
}
#endif

TEE_Result paillier_ta_encrypt_mock(uint32_t sensor_id, uint32_t fog_id,
				    uint32_t window_id,
				    int32_t reading_scaled,
				    uint32_t *out_fake_ciphertext)
{
	if (!out_fake_ciphertext)
		return TEE_ERROR_BAD_PARAMETERS;

	*out_fake_ciphertext = (uint32_t)reading_scaled +
			       sensor_id * 100 +
			       window_id * 10 +
			       fog_id;
	return TEE_SUCCESS;
}

TEE_Result paillier_ta_encrypt_real_u32(uint32_t m,
					uint8_t *out_ciphertext,
					uint32_t *out_len,
					uint32_t out_max_len)
{
#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
	mp_int n;
	mp_int g;
	mp_int n2;
	mp_int m_bn;
	mp_int r;
	mp_int gm;
	mp_int rn;
	mp_int c;
	mp_err err;
	TEE_Result res = TEE_SUCCESS;
	size_t written = 0;
	uint32_t padding_len;

	if (!out_ciphertext || !out_len ||
	    out_max_len < PAILLIER_TA_CIPHERTEXT_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	err = mp_init_multi(&n, &g, &n2, &m_bn, &r, &gm, &rn, &c, NULL);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);

	res = read_fixed_public_key(&n, &g, &n2);
	if (res != TEE_SUCCESS)
		goto out;

	mp_set_u32(&m_bn, m);

	res = generate_coprime_r(&n, &r);
	if (res != TEE_SUCCESS)
		goto out;

	err = mp_exptmod(&g, &m_bn, &n2, &gm);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	err = mp_exptmod(&r, &n, &n2, &rn);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	err = mp_mulmod(&gm, &rn, &n2, &c);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}

	TEE_MemFill(out_ciphertext, 0, PAILLIER_TA_CIPHERTEXT_BYTES);
	err = mp_to_ubin(&c, out_ciphertext, PAILLIER_TA_CIPHERTEXT_BYTES,
			 &written);
	if (err != MP_OKAY || written > PAILLIER_TA_CIPHERTEXT_BYTES) {
		res = err == MP_OKAY ? TEE_ERROR_BAD_FORMAT :
				       mp_err_to_tee(err);
		goto out;
	}

	padding_len = PAILLIER_TA_CIPHERTEXT_BYTES - (uint32_t)written;
	if (padding_len != 0)
		TEE_MemMove(out_ciphertext + padding_len, out_ciphertext,
			    written);
	TEE_MemFill(out_ciphertext, 0, padding_len);

	*out_len = PAILLIER_TA_CIPHERTEXT_BYTES;

out:
	mp_clear_multi(&n, &g, &n2, &m_bn, &r, &gm, &rn, &c, NULL);
	return res;
#else
	(void)m;
	(void)out_ciphertext;
	(void)out_len;
	(void)out_max_len;
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

TEE_Result paillier_ta_decrypt_real_u32(const uint8_t *ciphertext,
					uint32_t ciphertext_len,
					uint32_t *out_m)
{
#if SECURE_IIOT_ENABLE_REAL_PAILLIER_TA
	mp_int n;
	mp_int g;
	mp_int n2;
	mp_int lambda;
	mp_int mu;
	mp_int c;
	mp_int u;
	mp_int u_minus_one;
	mp_int l_value;
	mp_int remainder;
	mp_int m_bn;
	mp_err err;
	TEE_Result res = TEE_SUCCESS;

	if (!ciphertext || !out_m ||
	    ciphertext_len != PAILLIER_TA_CIPHERTEXT_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	err = mp_init_multi(&n, &g, &n2, &lambda, &mu, &c, &u, &u_minus_one,
			    &l_value, &remainder, &m_bn, NULL);
	if (err != MP_OKAY)
		return mp_err_to_tee(err);

	res = read_fixed_private_key(&n, &g, &n2, &lambda, &mu);
	if (res != TEE_SUCCESS)
		goto out;

	IMSG("Paillier TA decrypt: parse ciphertext");
	err = mp_from_ubin(&c, ciphertext, ciphertext_len);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	if (mp_cmp_d(&c, 0) != MP_GT || mp_cmp(&c, &n2) != MP_LT) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	err = mp_exptmod(&c, &lambda, &n2, &u);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	IMSG("Paillier TA decrypt: modular exponentiation completed");

	err = mp_sub_d(&u, 1, &u_minus_one);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	err = mp_div(&u_minus_one, &n, &l_value, &remainder);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	if (mp_cmp_d(&remainder, 0) != MP_EQ) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	err = mp_mulmod(&l_value, &mu, &n, &m_bn);
	if (err != MP_OKAY) {
		res = mp_err_to_tee(err);
		goto out;
	}
	if (mp_count_bits(&m_bn) > 32) {
		res = TEE_ERROR_OVERFLOW;
		goto out;
	}

	*out_m = mp_get_u32(&m_bn);
	IMSG("Paillier TA decrypt: plaintext aggregate recovered");

out:
	mp_clear_multi(&n, &g, &n2, &lambda, &mu, &c, &u, &u_minus_one,
		       &l_value, &remainder, &m_bn, NULL);
	return res;
#else
	(void)ciphertext;
	(void)ciphertext_len;
	(void)out_m;
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

TEE_Result paillier_ta_decrypt_aggregate_mock(
	uint32_t fake_paillier_aggregate,
	uint32_t *out_plaintext_aggregate)
{
	if (!out_plaintext_aggregate)
		return TEE_ERROR_BAD_PARAMETERS;

	*out_plaintext_aggregate = fake_paillier_aggregate;
	return TEE_SUCCESS;
}
