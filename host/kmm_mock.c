// SPDX-License-Identifier: BSD-2-Clause
/*
 * KMM mock control-plane implementation.
 *
 * No real attestation, key provisioning, CP-ABE, or delegated key material is
 * handled here. The state and logs are metadata-only placeholders that make
 * the paper's orchestration flow explicit for demos and later replacement.
 */

#include "kmm_mock.h"

#include <stdio.h>
#include <string.h>

static const char *fog_name(const kmm_mock_t *kmm, uint32_t fog_id)
{
	uint32_t i;

	for (i = 0; i < kmm->fog_count; i++) {
		if (kmm->fog_nodes[i].fog_id == fog_id &&
		    kmm->fog_nodes[i].name)
			return kmm->fog_nodes[i].name;
	}

	return "unknown";
}

static kmm_slot_entry_t *find_slot(kmm_mock_t *kmm, uint32_t sensor_id)
{
	uint32_t i;

	for (i = 0; i < kmm->slot_count; i++) {
		if (kmm->slot_map[i].sensor_id == sensor_id)
			return &kmm->slot_map[i];
	}

	return NULL;
}

static int set_slot(kmm_mock_t *kmm, uint32_t sensor_id, uint32_t fog_id)
{
	kmm_slot_entry_t *slot = find_slot(kmm, sensor_id);

	if (slot) {
		slot->assigned_fog_id = fog_id;
		return 0;
	}

	if (kmm->slot_count >=
	    sizeof(kmm->slot_map) / sizeof(kmm->slot_map[0]))
		return -1;

	kmm->slot_map[kmm->slot_count].sensor_id = sensor_id;
	kmm->slot_map[kmm->slot_count].assigned_fog_id = fog_id;
	kmm->slot_count++;
	return 0;
}

void kmm_init(kmm_mock_t *kmm)
{
	memset(kmm, 0, sizeof(*kmm));
	printf("[KMM] Init prototype control plane\n");
	printf("[KMM] Fog nodes never exchange AES keys directly; KMM provisions scoped delegated keys only.\n");
}

int kmm_register_fog(kmm_mock_t *kmm, uint32_t fog_id, const char *name,
		     uint32_t workload_percent)
{
	if (kmm->fog_count >=
	    sizeof(kmm->fog_nodes) / sizeof(kmm->fog_nodes[0]))
		return -1;

	kmm->fog_nodes[kmm->fog_count].fog_id = fog_id;
	kmm->fog_nodes[kmm->fog_count].name = name;
	kmm->fog_nodes[kmm->fog_count].registered = 1;
	kmm->fog_nodes[kmm->fog_count].workload_percent =
		workload_percent;
	kmm->fog_count++;

	printf("[KMM] Register Fog %s workload=%u%%\n", name,
	       workload_percent);
	return 0;
}

int kmm_assign_sensor(kmm_mock_t *kmm, uint32_t sensor_id, uint32_t fog_id)
{
	if (set_slot(kmm, sensor_id, fog_id) != 0)
		return -1;

	printf("[KMM] Assign Sensor S%u -> Fog %s\n", sensor_id,
	       fog_name(kmm, fog_id));
	return 0;
}

uint32_t kmm_get_assigned_fog(kmm_mock_t *kmm, uint32_t sensor_id)
{
	kmm_slot_entry_t *slot = find_slot(kmm, sensor_id);

	if (!slot)
		return 0;

	return slot->assigned_fog_id;
}

int kmm_verify_fog_quote(kmm_mock_t *kmm, uint32_t fog_id)
{
	printf("[KMM] Verify Fog %s quote: PASS (mock attestation)\n",
	       fog_name(kmm, fog_id));
	return 1;
}

int kmm_request_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			   uint32_t from_fog_id, uint32_t to_fog_id,
			   uint32_t window_id)
{
	(void)window_id;

	printf("[KMM] Delegation request: Sensor S%u from Fog %s to Fog %s\n",
	       sensor_id, fog_name(kmm, from_fog_id),
	       fog_name(kmm, to_fog_id));
	printf("[KMM] Fog %s notifies KMM; Fog %s does not receive kfog%u directly from Fog %s.\n",
	       fog_name(kmm, from_fog_id), fog_name(kmm, to_fog_id),
	       from_fog_id, fog_name(kmm, from_fog_id));
	return 0;
}

int kmm_provision_delegated_key(kmm_mock_t *kmm, uint32_t from_fog_id,
				uint32_t to_fog_id, uint32_t window_id)
{
	printf("[KMM] Provision kfog%u to Fog %s TA for window W=%u\n",
	       from_fog_id, fog_name(kmm, to_fog_id), window_id);
	printf("[KMM] Delegated key lifetime: one aggregation window only.\n");
	return 0;
}

int kmm_revoke_delegated_key(kmm_mock_t *kmm, uint32_t from_fog_id,
			     uint32_t to_fog_id, uint32_t window_id)
{
	printf("[KMM] Revoke delegated kfog%u from Fog %s after window close W=%u\n",
	       from_fog_id, fog_name(kmm, to_fog_id), window_id);
	return 0;
}

int kmm_receive_fog_aggregate(kmm_mock_t *kmm, uint32_t fog_id,
			      uint32_t window_id, uint32_t fake_cagg)
{
	printf("[KMM] Receive one aggregate ciphertext from Fog %s for window=%u value=%u\n",
	       fog_name(kmm, fog_id), window_id, fake_cagg);
	return 0;
}

uint32_t kmm_combine_fake_aggregates(uint32_t *aggregates,
				     uint32_t count)
{
	uint32_t i;
	uint32_t combined = 0;

	for (i = 0; i < count; i++)
		combined += aggregates[i];

	return combined;
}

uint32_t kmm_window_combine(kmm_mock_t *kmm, uint32_t window_id,
			    uint32_t *aggregates, uint32_t count)
{
	uint32_t combined;

	(void)kmm;
	printf("[KMM] Combine one aggregate ciphertext per fog node for window W=%u\n",
	       window_id);
	combined = kmm_combine_fake_aggregates(aggregates, count);
	return combined;
}

void kmm_prepare_storage(kmm_mock_t *kmm, uint32_t window_id)
{
	(void)kmm;
	printf("[KMM] Send final aggregate to Storage-Preparation TA for window W=%u\n",
	       window_id);
}

int kmm_authorize_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			     uint32_t source_fog_id,
			     uint32_t target_fog_id,
			     uint32_t window_id)
{
	kmm_delegation_t *delegation;

	if (kmm->delegation_count >=
	    sizeof(kmm->delegations) / sizeof(kmm->delegations[0]))
		return -1;

	delegation = &kmm->delegations[kmm->delegation_count++];
	delegation->sensor_id = sensor_id;
	delegation->source_fog_id = source_fog_id;
	delegation->target_fog_id = target_fog_id;
	delegation->window_id = window_id;
	delegation->active = 1;

	if (set_slot(kmm, sensor_id, target_fog_id) != 0)
		return -1;

	printf("[KMM] Delegation active: Sensor S%u from Fog %s to Fog %s for window W=%u\n",
	       sensor_id, fog_name(kmm, source_fog_id),
	       fog_name(kmm, target_fog_id), window_id);
	return 0;
}

int kmm_revoke_delegation(kmm_mock_t *kmm, uint32_t sensor_id,
			  uint32_t source_fog_id,
			  uint32_t target_fog_id,
			  uint32_t window_id)
{
	uint32_t i;

	for (i = 0; i < kmm->delegation_count; i++) {
		kmm_delegation_t *delegation = &kmm->delegations[i];

		if (delegation->sensor_id == sensor_id &&
		    delegation->source_fog_id == source_fog_id &&
		    delegation->target_fog_id == target_fog_id &&
		    delegation->window_id == window_id &&
		    delegation->active) {
			delegation->active = 0;
			printf("[KMM] Delegation state revoked: kfog%u at Fog %s for Sensor S%u window W=%u\n",
			       source_fog_id, fog_name(kmm, target_fog_id),
			       sensor_id, window_id);
			return 0;
		}
	}

	return -1;
}

void kmm_print_slot_map(const kmm_mock_t *kmm)
{
	uint32_t i;

	printf("KMM slot map:\n");
	for (i = 0; i < kmm->slot_count; i++) {
		printf("  sensor %u -> Fog %s\n", kmm->slot_map[i].sensor_id,
		       fog_name(kmm, kmm->slot_map[i].assigned_fog_id));
	}
}

void kmm_print_delegations(const kmm_mock_t *kmm)
{
	uint32_t i;

	printf("KMM delegations:\n");
	for (i = 0; i < kmm->delegation_count; i++) {
		const kmm_delegation_t *delegation = &kmm->delegations[i];

		printf("  sensor=%u %s -> %s window=%u active=%u\n",
		       delegation->sensor_id,
		       fog_name(kmm, delegation->source_fog_id),
		       fog_name(kmm, delegation->target_fog_id),
		       delegation->window_id, delegation->active);
	}
}
