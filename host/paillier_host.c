// SPDX-License-Identifier: BSD-2-Clause
/*
 * Host-side Paillier support.
 *
 * The mock functions remain available as the presentation fallback path. The
 * BIGNUM functions are a real Normal World reference implementation and a
 * verifier/aggregator for TA-produced Paillier ciphertexts.
 */

#include "paillier_host.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/*
 * Fixed demo key matching ta/paillier_ta.c.
 *
 * This deterministic 512-bit key is insecure and exists only for repeatable
 * prototype verification. Production should use at least 2048-bit Paillier
 * keys with the private key owned by Storage-Preparation TA, not the host.
 */
static const char PAILLIER_DEMO_N_HEX[] =
	"d2007a47121b1ea33ba8c1cc20b9011fff3aff9c15c830773b1b55de7c21b20f"
	"7a42be8d4dfc2a4eebc351acdbeb5e6b69c4fa1e537e1c8cb26352ee3dd4a38d";
static const char PAILLIER_DEMO_G_HEX[] =
	"d2007a47121b1ea33ba8c1cc20b9011fff3aff9c15c830773b1b55de7c21b20f"
	"7a42be8d4dfc2a4eebc351acdbeb5e6b69c4fa1e537e1c8cb26352ee3dd4a38e";
static const char PAILLIER_DEMO_N2_HEX[] =
	"ac44c89cd41c4f40b3674489447e8f2d2450afbeac4bb3408f9b33554acf6f3"
	"d4bf5e1261b42598d1453d5613312c9da3a496683aac2559ff20c2650723d463"
	"204a8ed0c62eb260facea94541ffe827d6d14a706c91e87e5201bf79456f7946"
	"97ba0e91aee73e572b979c064ecdd362158df90611e42bd71d22374bc7c04dba9";
static const char PAILLIER_DEMO_LAMBDA_HEX[] =
	"34801e91c486c7a8ceea3073082e4047ffcebfe705720c1dcec6d5779f086c83"
	"6a9d232f8da0b3f2060783d5ceacf5ecfe46401553f5d21d68087aea791755c8";
static const char PAILLIER_DEMO_MU_HEX[] =
	"9f4b9e3df00eacdbb148539d636842e9013deabcd55523378d87ba50ef8c0c70"
	"46b80127fcccdfed10fc793aeeae5a307792fb03b14bbe139963287be0a392aa";

void paillier_host_init_aggregate_mock(uint32_t *aggregate)
{
	*aggregate = 0;
}

void paillier_host_add_ciphertext_mock(uint32_t *aggregate,
				       uint32_t fake_ciphertext)
{
	*aggregate += fake_ciphertext;
}

uint32_t paillier_host_combine_aggregates_mock(const uint32_t *aggregates,
					       uint32_t count)
{
	uint32_t i;
	uint32_t combined = 0;

	for (i = 0; i < count; i++)
		combined += aggregates[i];

	return combined;
}

static int bn_set_word_checked(BIGNUM *bn, uint32_t value)
{
	return BN_set_word(bn, (BN_ULONG)value) == 1;
}

static int paillier_L_function(const BIGNUM *u, const BIGNUM *n,
			       BIGNUM *out_l, BN_CTX *ctx)
{
	BIGNUM *u_minus_one;
	int ok = 0;

	BN_CTX_start(ctx);
	u_minus_one = BN_CTX_get(ctx);
	if (!u_minus_one)
		goto out;

	if (BN_sub(u_minus_one, u, BN_value_one()) != 1)
		goto out;
	if (BN_div(out_l, NULL, u_minus_one, n, ctx) != 1)
		goto out;

	ok = 1;

out:
	BN_CTX_end(ctx);
	return ok;
}

/*
 * Demo key generation. The default caller uses 512-bit keys for QEMU speed and
 * prototype validation only. Production Paillier keys should be 2048-bit or
 * stronger, generated and protected according to the final threat model.
 */
int paillier_host_keygen_demo(paillier_host_keypair_t *kp, int bits)
{
	paillier_host_keypair_t tmp;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *p_minus_one = NULL;
	BIGNUM *q_minus_one = NULL;
	BIGNUM *gcd = NULL;
	BIGNUM *lcm_numer = NULL;
	BIGNUM *u = NULL;
	BIGNUM *l_value = NULL;
	int prime_bits;
	int ok = 0;

	if (!kp || bits < 32)
		return 0;

	memset(&tmp, 0, sizeof(tmp));
	prime_bits = bits / 2;

	tmp.ctx = BN_CTX_new();
	tmp.n = BN_new();
	tmp.n2 = BN_new();
	tmp.g = BN_new();
	tmp.lambda = BN_new();
	tmp.mu = BN_new();
	p = BN_new();
	q = BN_new();
	p_minus_one = BN_new();
	q_minus_one = BN_new();
	gcd = BN_new();
	lcm_numer = BN_new();
	u = BN_new();
	l_value = BN_new();
	if (!tmp.ctx || !tmp.n || !tmp.n2 || !tmp.g || !tmp.lambda ||
	    !tmp.mu || !p || !q || !p_minus_one || !q_minus_one || !gcd ||
	    !lcm_numer || !u || !l_value)
		goto out;

	if (BN_generate_prime_ex(p, prime_bits, 0, NULL, NULL, NULL) != 1)
		goto out;
	do {
		if (BN_generate_prime_ex(q, bits - prime_bits, 0,
					 NULL, NULL, NULL) != 1)
			goto out;
	} while (BN_cmp(p, q) == 0);

	if (BN_mul(tmp.n, p, q, tmp.ctx) != 1)
		goto out;
	if (BN_mul(tmp.n2, tmp.n, tmp.n, tmp.ctx) != 1)
		goto out;
	if (BN_copy(tmp.g, tmp.n) == NULL)
		goto out;
	if (BN_add(tmp.g, tmp.g, BN_value_one()) != 1)
		goto out;

	if (BN_sub(p_minus_one, p, BN_value_one()) != 1)
		goto out;
	if (BN_sub(q_minus_one, q, BN_value_one()) != 1)
		goto out;
	if (BN_gcd(gcd, p_minus_one, q_minus_one, tmp.ctx) != 1)
		goto out;
	if (BN_mul(lcm_numer, p_minus_one, q_minus_one, tmp.ctx) != 1)
		goto out;
	if (BN_div(tmp.lambda, NULL, lcm_numer, gcd, tmp.ctx) != 1)
		goto out;

	if (BN_mod_exp(u, tmp.g, tmp.lambda, tmp.n2, tmp.ctx) != 1)
		goto out;
	if (!paillier_L_function(u, tmp.n, l_value, tmp.ctx))
		goto out;
	if (!BN_mod_inverse(tmp.mu, l_value, tmp.n, tmp.ctx))
		goto out;

	*kp = tmp;
	memset(&tmp, 0, sizeof(tmp));
	ok = 1;

out:
	paillier_host_keypair_free(&tmp);
	BN_free(p);
	BN_free(q);
	BN_free(p_minus_one);
	BN_free(q_minus_one);
	BN_free(gcd);
	BN_free(lcm_numer);
	BN_free(u);
	BN_free(l_value);
	return ok;
}

static int bn_hex2bn_checked(BIGNUM **bn, const char *hex)
{
	return BN_hex2bn(bn, hex) != 0;
}

int paillier_host_init_fixed_demo_key(paillier_host_keypair_t *kp)
{
	paillier_host_keypair_t tmp;
	int ok = 0;

	if (!kp)
		return 0;

	memset(&tmp, 0, sizeof(tmp));
	tmp.ctx = BN_CTX_new();
	if (!tmp.ctx)
		goto out;

	if (!bn_hex2bn_checked(&tmp.n, PAILLIER_DEMO_N_HEX) ||
	    !bn_hex2bn_checked(&tmp.g, PAILLIER_DEMO_G_HEX) ||
	    !bn_hex2bn_checked(&tmp.n2, PAILLIER_DEMO_N2_HEX) ||
	    !bn_hex2bn_checked(&tmp.lambda, PAILLIER_DEMO_LAMBDA_HEX) ||
	    !bn_hex2bn_checked(&tmp.mu, PAILLIER_DEMO_MU_HEX))
		goto out;

	*kp = tmp;
	memset(&tmp, 0, sizeof(tmp));
	ok = 1;

out:
	paillier_host_keypair_free(&tmp);
	return ok;
}

void paillier_host_keypair_free(paillier_host_keypair_t *kp)
{
	if (!kp)
		return;

	BN_free(kp->n);
	BN_free(kp->n2);
	BN_free(kp->g);
	BN_free(kp->lambda);
	BN_free(kp->mu);
	BN_CTX_free(kp->ctx);
	memset(kp, 0, sizeof(*kp));
}

int paillier_host_encrypt_u32(const paillier_host_keypair_t *kp,
			      uint32_t m, BIGNUM **out_c)
{
	BIGNUM *ciphertext = NULL;
	BIGNUM *m_bn;
	BIGNUM *r;
	BIGNUM *gcd;
	BIGNUM *gm;
	BIGNUM *rn;
	int ok = 0;

	if (!kp || !kp->n || !kp->n2 || !kp->g || !kp->ctx || !out_c)
		return 0;

	BN_CTX_start(kp->ctx);
	m_bn = BN_CTX_get(kp->ctx);
	r = BN_CTX_get(kp->ctx);
	gcd = BN_CTX_get(kp->ctx);
	gm = BN_CTX_get(kp->ctx);
	rn = BN_CTX_get(kp->ctx);
	if (!rn)
		goto out;

	ciphertext = BN_new();
	if (!ciphertext || !bn_set_word_checked(m_bn, m))
		goto out;

	do {
		if (BN_rand_range(r, kp->n) != 1)
			goto out;
		if (BN_is_zero(r))
			continue;
		if (BN_gcd(gcd, r, kp->n, kp->ctx) != 1)
			goto out;
	} while (!BN_is_one(gcd));

	if (BN_mod_exp(gm, kp->g, m_bn, kp->n2, kp->ctx) != 1)
		goto out;
	if (BN_mod_exp(rn, r, kp->n, kp->n2, kp->ctx) != 1)
		goto out;
	if (BN_mod_mul(ciphertext, gm, rn, kp->n2, kp->ctx) != 1)
		goto out;

	*out_c = ciphertext;
	ciphertext = NULL;
	ok = 1;

out:
	BN_free(ciphertext);
	BN_CTX_end(kp->ctx);
	return ok;
}

int paillier_host_add_ciphertexts_real(const paillier_host_keypair_t *kp,
				       const BIGNUM *c1,
				       const BIGNUM *c2,
				       BIGNUM **out_c)
{
	BIGNUM *sum = NULL;

	if (!kp || !kp->n2 || !kp->ctx || !c1 || !c2 || !out_c)
		return 0;

	sum = BN_new();
	if (!sum)
		return 0;

	if (BN_mod_mul(sum, c1, c2, kp->n2, kp->ctx) != 1) {
		BN_free(sum);
		return 0;
	}

	*out_c = sum;
	return 1;
}

int paillier_host_init_aggregate_real(BIGNUM **out_aggregate)
{
	BIGNUM *aggregate;

	if (!out_aggregate)
		return 0;

	aggregate = BN_new();
	if (!aggregate)
		return 0;
	if (BN_one(aggregate) != 1) {
		BN_free(aggregate);
		return 0;
	}

	*out_aggregate = aggregate;
	return 1;
}

int paillier_host_add_ciphertext_bytes_real(
	const paillier_host_keypair_t *kp, BIGNUM **aggregate,
	const uint8_t *ciphertext, size_t ciphertext_len)
{
	BIGNUM *ci = NULL;
	BIGNUM *next = NULL;

	if (!kp || !aggregate || !*aggregate || !ciphertext)
		return 0;

	if (!paillier_host_fixed_bytes_to_bn(ciphertext, ciphertext_len, &ci))
		goto err;
	if (!paillier_host_add_ciphertexts_real(kp, *aggregate, ci, &next))
		goto err;

	BN_free(*aggregate);
	*aggregate = next;
	BN_free(ci);
	return 1;

err:
	BN_free(ci);
	BN_free(next);
	return 0;
}

int paillier_host_decrypt_u32(const paillier_host_keypair_t *kp,
			      const BIGNUM *c, uint32_t *out_m)
{
	BIGNUM *u;
	BIGNUM *l_value;
	BIGNUM *m_bn;
	int ok = 0;

	if (!kp || !kp->n || !kp->n2 || !kp->lambda || !kp->mu ||
	    !kp->ctx || !c || !out_m)
		return 0;

	BN_CTX_start(kp->ctx);
	u = BN_CTX_get(kp->ctx);
	l_value = BN_CTX_get(kp->ctx);
	m_bn = BN_CTX_get(kp->ctx);
	if (!m_bn)
		goto out;

	if (BN_mod_exp(u, c, kp->lambda, kp->n2, kp->ctx) != 1)
		goto out;
	if (!paillier_L_function(u, kp->n, l_value, kp->ctx))
		goto out;
	if (BN_mod_mul(m_bn, l_value, kp->mu, kp->n, kp->ctx) != 1)
		goto out;
	if (BN_num_bits(m_bn) > 32)
		goto out;

	*out_m = (uint32_t)BN_get_word(m_bn);
	ok = 1;

out:
	BN_CTX_end(kp->ctx);
	return ok;
}

int paillier_host_bn_to_fixed_bytes(const BIGNUM *bn, uint8_t *out,
				    size_t out_len)
{
	if (!bn || !out || out_len > INT_MAX)
		return 0;

	return BN_bn2binpad(bn, out, (int)out_len) == (int)out_len;
}

int paillier_host_fixed_bytes_to_bn(const uint8_t *in, size_t in_len,
				    BIGNUM **out_bn)
{
	BIGNUM *bn;

	if (!in || !out_bn || in_len > INT_MAX)
		return 0;

	bn = BN_bin2bn(in, (int)in_len, NULL);
	if (!bn)
		return 0;

	*out_bn = bn;
	return 1;
}

void paillier_host_ciphertext_preview_hex(const uint8_t *ciphertext,
					  size_t ciphertext_len,
					  size_t preview_len,
					  char *out_hex,
					  size_t out_hex_len)
{
	size_t bytes_to_print;
	size_t i;

	if (!out_hex || out_hex_len == 0)
		return;

	out_hex[0] = '\0';
	if (!ciphertext)
		return;

	bytes_to_print = ciphertext_len < preview_len ? ciphertext_len :
							 preview_len;
	if (out_hex_len < bytes_to_print * 2 + 1)
		return;

	for (i = 0; i < bytes_to_print; i++)
		snprintf(out_hex + (i * 2), out_hex_len - (i * 2),
			 "%02x", ciphertext[i]);
}
