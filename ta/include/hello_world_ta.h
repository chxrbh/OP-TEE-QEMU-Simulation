/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_HELLO_WORLD_H
#define TA_HELLO_WORLD_H

#include <stdint.h>

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_HELLO_WORLD_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

/* The function IDs implemented in this TA */
#define TA_HELLO_WORLD_CMD_INC_VALUE		0
#define TA_HELLO_WORLD_CMD_DEC_VALUE		1
#define TA_HELLO_WORLD_CMD_PROCESS_SENSOR_PACKET	2
#define TA_HELLO_WORLD_CMD_PREPARE_STORAGE	3

/* Backward-compatible alias for the previous prototype stage. */
#define TA_HELLO_WORLD_CMD_PROCESS_READING \
	TA_HELLO_WORLD_CMD_PROCESS_SENSOR_PACKET

/*
 * Current Secure IIoT stage:
 * Normal World sends an AES-GCM encrypted sensor packet and the TA decrypts
 * and authenticates it inside Secure World. Paillier encryption may be real or
 * mocked depending on the TA compile-time setting.
 */
#define TA_SECURE_IIOT_CMD_PROCESS_AES_PACKET \
	TA_HELLO_WORLD_CMD_PROCESS_SENSOR_PACKET
#define TA_SECURE_IIOT_CMD_PREPARE_STORAGE \
	TA_HELLO_WORLD_CMD_PREPARE_STORAGE

/*
 * Paillier ciphertext sizes used by the prototype.
 *
 * The live TA demo currently uses a 512-bit Paillier public modulus n, so
 * ciphertexts modulo n^2 are 1024 bits = 128 bytes. Keep the shared host/TA
 * ABI at this live demo size. The 2048-bit constants are for the host-side
 * benchmark/reference path only and must not silently resize TA structs.
 */
#define SECURE_IIOT_PAILLIER_DEMO_KEY_BITS 512
#define SECURE_IIOT_PAILLIER_DEMO_CIPHERTEXT_LEN 128
#define SECURE_IIOT_PAILLIER_2048_KEY_BITS 2048
#define SECURE_IIOT_PAILLIER_2048_CIPHERTEXT_LEN 512
#define SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX \
	SECURE_IIOT_PAILLIER_DEMO_CIPHERTEXT_LEN

typedef struct {
	uint32_t sensor_id;
	uint32_t fog_id;
	uint32_t window_id;
	uint64_t timestamp_ms;
	uint32_t plaintext_len;
	uint8_t nonce[12];
	uint8_t ciphertext[64];
	uint32_t ciphertext_len;
	uint8_t tag[16];
} secure_sensor_packet_t;

typedef struct {
	uint32_t sensor_id;
	uint32_t fog_id;
	uint32_t window_id;
	int32_t reading_scaled;
	uint64_t timestamp_ms;
} sensor_plaintext_t;

typedef struct {
	uint32_t sensor_id;
	uint32_t fog_id;
	uint32_t window_id;

	/*
	 * If real_paillier_enabled = 0:
	 *   fake_paillier_ciphertext is used.
	 *
	 * If real_paillier_enabled = 1:
	 *   paillier_ciphertext contains big-endian Paillier ciphertext bytes.
	 */
	uint32_t fake_paillier_ciphertext;
	uint8_t paillier_ciphertext[SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX];
	uint32_t paillier_ciphertext_len;

	uint32_t scaled_value;
	uint32_t real_paillier_enabled;
	uint32_t status;
} secure_sensor_result_t;

typedef struct {
	uint32_t window_id;
	uint32_t fog_count;

	/*
	 * Mock mode:
	 *   fake_paillier_aggregate is used.
	 *
	 * Real mode:
	 *   paillier_aggregate contains big-endian real Paillier ciphertext.
	 */
	uint32_t fake_paillier_aggregate;
	uint8_t paillier_aggregate[SECURE_IIOT_PAILLIER_CIPHERTEXT_MAX];
	uint32_t paillier_aggregate_len;
	uint32_t real_paillier_enabled;

	uint64_t timestamp_ms;
} storage_prep_input_t;

typedef struct {
	uint32_t window_id;
	uint32_t plaintext_aggregate;
	uint64_t timestamp_ms;
} storage_plaintext_t;

typedef struct {
	uint32_t window_id;
	uint8_t nonce[12];
	uint8_t ciphertext[64];
	uint32_t ciphertext_len;
	uint8_t tag[16];
	uint32_t status;
} storage_cloud_object_t;

#endif /*TA_HELLO_WORLD_H*/
