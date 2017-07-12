/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/ratchet.h"
#include "utils.h"

static int keypair(buffer_t *private_key, buffer_t *public_key) {
	return crypto_box_keypair(public_key->content, private_key->content);
}

int main(void) {
	int status_int = sodium_init();
	if (status_int != 0) {
		return status_int;
	}

	return_status status = return_status_init();

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
	if (keypair(alice_private_identity, alice_public_identity) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate Alice' identity keypair.");
	}
	if (keypair(alice_private_ephemeral, alice_public_ephemeral) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate Alice' ephemeral keypair.");
	}
	if (keypair(bob_private_identity, bob_public_identity) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate Bobs identity keypair.");
	}
	if (keypair(bob_private_ephemeral, bob_public_ephemeral) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate Bobs ephemeral keypair.");
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
	status = ratchet_create(
			&alice_send_ratchet,
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create Alice' send ratchet.");
	status = ratchet_create(
			&alice_receive_ratchet,
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create Alice' receive ratchet.");
	//Bob
	status = ratchet_create(
			&bob_send_ratchet,
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create Bobs send ratchet.");
	status = ratchet_create(
			&bob_receive_ratchet,
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create Bobs receive ratchet.");

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
	throw_on_error(DATA_FETCH_ERROR, "Failed to get send keys.");

	//bob receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			bob_receive_ratchet);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get receive header keys.");

	ratchet_header_decryptability decryptability;
	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(bob_receive_ratchet, decryptability);
	throw_on_error(DATA_SET_ERROR, "Failed to set header decryptability.");

	status = ratchet_receive(
			bob_receive_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get receive message key.");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		throw(INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key.");
	}
	printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

	status = ratchet_set_last_message_authenticity(bob_receive_ratchet, true);
	throw_on_error(DATA_SET_ERROR, "Bob-Receive: Failed to set message authenticity.");


	//SECOND SCENARIO: BOB SENDS MESSAGE TO ALICE
	status = ratchet_send(
			bob_send_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	throw_on_error(DATA_FETCH_ERROR, "Bob-Send: Failed to get send keys.");

	//alice receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			alice_receive_ratchet);
	throw_on_error(DATA_FETCH_ERROR, "Alice-Receive: Failed to get receive header keys.");

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(alice_receive_ratchet, decryptability);
	throw_on_error(DATA_SET_ERROR, "Alice-Receive: Failed to set header decryptability.");

	status = ratchet_receive(
			alice_receive_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	throw_on_error(RECEIVE_ERROR, "Alice-Receive: Failed to get receive message key.");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		throw(INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key.");
	}
	printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

	status = ratchet_set_last_message_authenticity(alice_receive_ratchet, true);
	throw_on_error(DATA_SET_ERROR, "Alice-Receive: Failed to set message authenticity.");

	//THIRD SCENARIO: BOB ANSWERS ALICE AFTER HAVING RECEIVED HER FIRST MESSAGE
	status = ratchet_send(
			bob_receive_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	throw_on_error(DATA_FETCH_ERROR, "Bob-Response: Failed to get send keys.");

	//alice receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			alice_send_ratchet);
	throw_on_error(DATA_FETCH_ERROR, "Alice-Roundtrip: Failed to get receive header keys.");

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(alice_send_ratchet, decryptability);
	throw_on_error(DATA_SET_ERROR, "Alice-Roundtrip: Failed  to set header decryptability.");

	status = ratchet_receive(
			alice_send_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	throw_on_error(RECEIVE_ERROR, "Alice-Roundtrip: Failed to get receive message key.");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		throw(INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key.");
	}
	printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

	status = ratchet_set_last_message_authenticity(alice_send_ratchet, true);
	throw_on_error(DATA_SET_ERROR, "Alice-Roundtrip: Failed to set message authenticity.");

	//FOURTH SCENARIO: ALICE ANSWERS BOB AFTER HAVING RECEIVED HER FIRST MESSAGE
	status = ratchet_send(
			alice_receive_ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			public_send_ephemeral,
			send_message_key);
	throw_on_error(DATA_FETCH_ERROR, "Bob-Roundtrip: Failed to get send-keys.");

	//bob receives
	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			bob_send_ratchet);
	throw_on_error(DATA_FETCH_ERROR, "Bob-Roundtrip: Failed to get receive header keys.");

	if (buffer_compare(send_header_key, current_receive_header_key) == 0) {
		decryptability = CURRENT_DECRYPTABLE;
	} else if (buffer_compare(send_header_key, next_receive_header_key) == 0) {
		decryptability = NEXT_DECRYPTABLE;
	} else {
		decryptability = UNDECRYPTABLE;
	}
	status = ratchet_set_header_decryptability(bob_send_ratchet, decryptability);
	throw_on_error(DATA_SET_ERROR, "Bob-Roundtrip: Failed to set header decryptability.");

	status = ratchet_receive(
			bob_send_ratchet,
			receive_message_key,
			public_send_ephemeral,
			send_message_number,
			previous_send_message_number);
	throw_on_error(RECEIVE_ERROR, "Bob-Roundtrip: Failed to get receive message key.");

	//now check if the message key is the same
	if (buffer_compare(send_message_key, receive_message_key) != 0) {
		throw(INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key.");
	}
	printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

	status = ratchet_set_last_message_authenticity(bob_send_ratchet, true);
	throw_on_error(DATA_SET_ERROR, "Bob-Roundtrip: Failed to set message authenticity.");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(alice_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(alice_public_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_ephemeral);

	buffer_destroy_from_heap_and_null_if_valid(send_header_key);
	buffer_destroy_from_heap_and_null_if_valid(send_message_key);
	buffer_destroy_from_heap_and_null_if_valid(public_send_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(current_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(next_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(receive_message_key);

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

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
