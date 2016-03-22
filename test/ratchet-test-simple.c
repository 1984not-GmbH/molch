/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/ratchet.h"
#include "../lib/json.h"
#include "tracing.h"

int keypair(buffer_t *private_key, buffer_t *public_key) {
	return crypto_box_keypair(public_key->content, private_key->content);
}

void export_ratchet(const ratchet_state *const ratchet, const char * const filename) {
	FILE *file = fopen(filename, "w");
	if (file == NULL) {
		return;
	}

	JSON_EXPORT(json, 100000, 4000, true, ratchet, ratchet_json_export);
	if (json == NULL) {
		fclose(file);
		return;
	}

	fprintf(file, "%.*s", (int)json->content_length, json->content);
	fclose(file);

	buffer_destroy_from_heap(json);
}

int main(void) {
	int status = sodium_init();
	if (status != 0) {
		return status;
	}

	//create all the buffers
	//Keys:
	//Alice:
	buffer_t *alice_private_identity = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *alice_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *alice_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *alice_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//Bob
	buffer_t *bob_private_identity = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *bob_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//keys for sending
	buffer_t *send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *send_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	buffer_t *public_send_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//keys for receiving
	buffer_t *current_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *next_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *receive_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);

	//ratchets
	ratchet_state *alice_send_ratchet = NULL;
	ratchet_state *alice_receive_ratchet = NULL;
	ratchet_state *bob_send_ratchet = NULL;
	ratchet_state *bob_receive_ratchet = NULL;

	//generate the keys
	status = keypair(alice_private_identity, alice_public_identity);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice' idendity kepair! (%i)\n", status);
		goto cleanup;
	}
	status = keypair(alice_private_ephemeral, alice_public_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice' ephemeral keypair! (%i)\n", status);
		goto cleanup;
	}
	status = keypair(bob_private_identity, bob_public_identity);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bobs identity keypair! (%i)\n", status);
		goto cleanup;
	}
	status = keypair(bob_private_ephemeral, bob_public_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bobs ephemeral keypair! (%i)\n", status);
		goto cleanup;
	}

	//compare public identity keys, the one with the bigger key will be alice
	//(to make the test more predictable, and make the 'am_i_alice' flag in the
	// ratchet match the names here)
	if (sodium_compare(bob_public_identity->content, alice_public_identity->content, PUBLIC_KEY_SIZE) > 0) {
		//swap bob and alice
		//public identity key
		buffer_t *stash = alice_public_identity;
		alice_public_identity = bob_public_identity;
		bob_public_identity = stash;

		//private identity key
		stash = alice_private_identity;
		alice_private_identity = bob_private_identity;
		bob_private_identity = stash;
	}

	//initialise the ratchets
	//Alice
	alice_send_ratchet = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	if (alice_send_ratchet == NULL) {
		fprintf(stderr, "ERROR: Failed to create Alice' send ratchet.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	export_ratchet(alice_send_ratchet, "alice-send-ratchet-initial.json");
	alice_receive_ratchet = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	if (alice_receive_ratchet == NULL) {
		fprintf(stderr, "ERROR: Failed to create Alice' receive ratchet.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	export_ratchet(alice_send_ratchet, "alice-receive-ratchet-initial.json");
	//Bob
	bob_send_ratchet = ratchet_create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	if (bob_send_ratchet == NULL) {
		fprintf(stderr, "ERROR: Failed to create Bobs send ratchet.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	export_ratchet(bob_send_ratchet, "bob-send-ratchet-initial.json");
	bob_receive_ratchet = ratchet_create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	if (bob_receive_ratchet == NULL) {
		fprintf(stderr, "ERROR: Failed to create Bobs receive ratchet.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	export_ratchet(bob_send_ratchet, "bob-receive-ratchet-initial.json");

	// FIRST SCENARIO: ALICE SENDS A MESSAGE TO BOB
	uint32_t send_message_number;
	uint32_t previous_send_message_number;
	status = ratchet_send(
			alice_send_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Send: Failed to get send keys. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(alice_send_ratchet, "alice-send-ratchet-after-sending.json");

	//bob receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			bob_receive_ratchet);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Receive: Failed to get receive header keys. (%i)\n", status);
		goto cleanup;
	}

	ratchet_header_decryptability decryptability;
	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(bob_receive_ratchet, decryptability);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Receive: Failed to set header decryptability. (%i)\n", status);
		goto cleanup;
	}

	status = ratchet_receive(
			bob_receive_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Receive: Failed to get receive message key. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(bob_receive_ratchet, "bob-receive-ratchet-after-receiving.json");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		fprintf(stderr, "ERROR: Bobs receive message key isn't the same as Alice' send message key.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

	status = ratchet_set_last_message_authenticity(bob_receive_ratchet, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Receive: Failed to set message authenticity. (%i)\n", status);
		goto cleanup;
	}


	//SECOND SCENARIO: BOB SENDS MESSAGE TO ALICE
	status = ratchet_send(
			bob_send_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Send: Failed to get send keys. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(bob_send_ratchet, "bob-send-ratchet-after-sending.json");

	//alice receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			alice_receive_ratchet);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Receive: Failed to get receive header keys. (%i)\n", status);
		goto cleanup;
	}

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(alice_receive_ratchet, decryptability);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Receive: Failed to set header decryptability. (%i)\n", status);
		goto cleanup;
	}

	status = ratchet_receive(
			alice_receive_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Receive: Failed to get receive message key. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(alice_receive_ratchet, "alice-receive-ratchet-after-receiving.json");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		fprintf(stderr, "ERROR: Alice' receive message key isn't the same as Bobs send message key.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

	status = ratchet_set_last_message_authenticity(alice_receive_ratchet, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Receive: Failed to set message authenticity. (%i)\n", status);
		goto cleanup;
	}

	//THIRD SCENARIO: BOB ANSWERS ALICE AFTER HAVING RECEIVED HER FIRST MESSAGE
	status = ratchet_send(
			bob_receive_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Response: Failed to get send keys. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(bob_receive_ratchet, "bob-receive-ratchet-after-responding.json");

	//alice receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			alice_send_ratchet);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Roundtrip: Failed to get receive header keys. (%i)\n", status);
		goto cleanup;
	}

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(alice_send_ratchet, decryptability);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Roundtrip: Failed to set header decryptability. (%i)\n", status);
		goto cleanup;
	}

	status = ratchet_receive(
			alice_send_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Roundtrip: Failed to get receive message key. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(alice_send_ratchet, "alice-send-ratchet-after-receiving.json");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		fprintf(stderr, "ERROR: Alice' receive message key isn't the same as Bobs send message key.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

	status = ratchet_set_last_message_authenticity(alice_send_ratchet, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice-Roundtrip: Failed to set message authenticity. (%i)\n", status);
		goto cleanup;
	}

	//FOURTH SCENARIO: ALICE ANSWERS BOB AFTER HAVING RECEIVED HER FIRST MESSAGE
	status = ratchet_send(
			alice_receive_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Roundtrip: Failed to get send-keys. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(alice_receive_ratchet, "alice-receive-ratchet-after-responding.json");

	//bob receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			bob_send_ratchet);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Roundtrip: Failed to get receive header keys. (%i)\n", status);
		goto cleanup;
	}

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(bob_send_ratchet, decryptability);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Roundtrip: Failed to set header decryptability. (%i)\n", status);
		goto cleanup;
	}

	status = ratchet_receive(
			bob_send_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Roundtrip: Failed to get receive message key. (%i)\n", status);
		goto cleanup;
	}
	export_ratchet(bob_send_ratchet, "bob-send-ratchet-after-receiving.json");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		fprintf(stderr, "ERROR: Bobs receive message key isn't the same as Alice' send message key.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

	status = ratchet_set_last_message_authenticity(bob_send_ratchet, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Bob-Roundtrip: Failed to set message authenticity. (%i)\n", status);
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(alice_public_ephemeral);
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(bob_public_ephemeral);

	buffer_destroy_from_heap(send_header_key);
	buffer_destroy_from_heap(send_message_key);
	buffer_destroy_from_heap(public_send_ephemeral);
	buffer_destroy_from_heap(current_receive_header_key);
	buffer_destroy_from_heap(next_receive_header_key);
	buffer_destroy_from_heap(receive_message_key);

	if (alice_send_ratchet != NULL) {
		ratchet_destroy(alice_send_ratchet);
	}
	if (alice_receive_ratchet != NULL) {
		ratchet_destroy(alice_receive_ratchet);
	}
	if (bob_send_ratchet != NULL) {
		ratchet_destroy(bob_send_ratchet);
	}
	if (bob_receive_ratchet != NULL) {
		ratchet_destroy(bob_receive_ratchet);
	}

	return status;
}
