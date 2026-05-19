// SPDX-License-Identifier: BSD-2-Clause
/*
 * Host-side KMM control-plane mock for the Secure IIoT prototype.
 *
 * This module does not perform real attestation and does not provision real
 * keys. It models the paper's KMM control-plane decisions with readable logs:
 * fog registration, fog-scoped metadata, slot assignment, window combine,
 * delegation authorization/revocation, and cloud object metadata narration.
 */

#ifndef SECURE_IIOT_KMM_MOCK_H
#define SECURE_IIOT_KMM_MOCK_H

#include <stdint.h>

typedef struct {
	uint32_t fog_id;
	const char *name;
	uint32_t registered;
	uint32_t workload_percent;
} kmm_fog_node_t;

typedef struct {
	uint32_t sensor_id;
	uint32_t assigned_fog_id;
} kmm_slot_entry_t;

typedef struct {
	uint32_t source_fog_id;
	uint32_t target_fog_id;
	uint32_t sensor_id;
	uint32_t window_id;
	uint32_t active;
} kmm_delegation_t;

typedef struct {
	kmm_fog_node_t fog_nodes[8];
	uint32_t fog_count;

	kmm_slot_entry_t slot_map[32];
	uint32_t slot_count;

	kmm_delegation_t delegations[32];
	uint32_t delegation_count;
} kmm_mock_t;

void kmm_init(kmm_mock_t *kmm);

int kmm_register_fog(kmm_mock_t *kmm, uint32_t fog_id, const char *name,
		     uint32_t workload_percent);

int kmm_assign_sensor(kmm_mock_t *kmm, uint32_t sensor_id,
		      uint32_t fog_id);

uint32_t kmm_get_assigned_fog(kmm_mock_t *kmm, uint32_t sensor_id);

int kmm_verify_fog_quote(kmm_mock_t *kmm, uint32_t fog_id);

int kmm_request_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			   uint32_t from_fog_id, uint32_t to_fog_id,
			   uint32_t window_id);

int kmm_provision_delegated_key(kmm_mock_t *kmm, uint32_t from_fog_id,
				uint32_t to_fog_id, uint32_t window_id);

int kmm_revoke_delegated_key(kmm_mock_t *kmm, uint32_t from_fog_id,
			     uint32_t to_fog_id, uint32_t window_id);

int kmm_receive_fog_aggregate(kmm_mock_t *kmm, uint32_t fog_id,
			      uint32_t window_id, uint32_t fake_cagg);

uint32_t kmm_combine_fake_aggregates(uint32_t *aggregates,
				     uint32_t count);

uint32_t kmm_window_combine(kmm_mock_t *kmm, uint32_t window_id,
			    uint32_t *aggregates, uint32_t count);

void kmm_prepare_storage(kmm_mock_t *kmm, uint32_t window_id);

int kmm_authorize_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			     uint32_t source_fog_id,
			     uint32_t target_fog_id,
			     uint32_t window_id);

int kmm_revoke_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			  uint32_t source_fog_id,
			  uint32_t target_fog_id,
			  uint32_t window_id);

void kmm_print_slot_map(const kmm_mock_t *kmm);
void kmm_print_delegations(const kmm_mock_t *kmm);

#endif /* SECURE_IIOT_KMM_MOCK_H */
