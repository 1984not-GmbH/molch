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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <cassert>

#include "../lib/ratchet.h"
#include "utils.h"
#include "common.h"

return_status protobuf_export(
		ratchet_state * const ratchet,
		Buffer ** const export_buffer) __attribute__((warn_unused_result));
return_status protobuf_export(
		ratchet_state * const ratchet,
		Buffer ** const export_buffer) {
	return_status status = return_status_init();

	Conversation * conversation = nullptr;

	//check input
	if ((ratchet == nullptr) || (export_buffer == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	//export
	status = ratchet_export(ratchet, &conversation);
	THROW_on_error(EXPORT_ERROR, "Failed to export ratchet.");

	{
		size_t export_size = conversation__get_packed_size(conversation);
		*export_buffer = Buffer::create(export_size, 0);
		(*export_buffer)->content_length = conversation__pack(conversation, (*export_buffer)->content);
		if (export_size != (*export_buffer)->content_length) {
			THROW(EXPORT_ERROR, "Failed to export ratchet.");
		}
	}

cleanup:
	if (conversation != nullptr) {
		conversation__free_unpacked(conversation, &protobuf_c_allocators);
	}

	//buffer will be freed in main

	return status;
}

return_status protobuf_import(
		ratchet_state ** const ratchet,
		const Buffer * const export_buffer) __attribute__((warn_unused_result));
return_status protobuf_import(
		ratchet_state ** const ratchet,
		const Buffer * const export_buffer) {
	return_status status = return_status_init();

	Conversation *conversation = nullptr;

	//check input
	if ((ratchet == nullptr) || (export_buffer == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	//unpack the buffer
	conversation = conversation__unpack(
		&protobuf_c_allocators,
		export_buffer->content_length,
		export_buffer->content);
	if (conversation == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
	}

	//now do the import
	status = ratchet_import(
		ratchet,
		conversation);
	THROW_on_error(IMPORT_ERROR, "Failed to import from Protobuf-C.");

cleanup:
	if (conversation != nullptr) {
		conversation__free_unpacked(conversation, &protobuf_c_allocators);
	}
	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//protobuf buffers
	Buffer *protobuf_export_buffer = nullptr;
	Buffer *protobuf_second_export_buffer = nullptr;

	ratchet_state *alice_state = nullptr;
	ratchet_state *bob_state = nullptr;
	ratchet_header_decryptability decryptable = NOT_TRIED;

	int status_int;

	//create all the buffers
	//alice keys
	Buffer *alice_private_identity = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *alice_public_identity = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *alice_private_ephemeral = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *alice_public_ephemeral = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//bob keys
	Buffer *bob_private_identity = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *bob_public_identity = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *bob_private_ephemeral = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *bob_public_ephemeral = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//alice send message and header keys
	Buffer *alice_send_message_key1 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_send_header_key1 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *alice_send_ephemeral1 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	Buffer *alice_send_message_key2 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_send_header_key2 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *alice_send_ephemeral2 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	Buffer *alice_send_message_key3 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_send_header_key3 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *alice_send_ephemeral3 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	//bobs receive keys
	Buffer *bob_current_receive_header_key = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *bob_next_receive_header_key = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_receive_key1 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_receive_key2 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_receive_key3 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	//bobs śend message and header keys
	Buffer *bob_send_message_key1 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_send_header_key1 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *bob_send_ephemeral1 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	Buffer *bob_send_message_key2 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_send_header_key2 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *bob_send_ephemeral2 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	Buffer *bob_send_message_key3 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *bob_send_header_key3 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *bob_send_ephemeral3 = Buffer::create(PUBLIC_KEY_SIZE, 0);
	//alice receive keys
	Buffer *alice_current_receive_header_key = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *alice_next_receive_header_key = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_receive_message_key1 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_receive_message_key2 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_receive_message_key3 = Buffer::create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	Buffer *alice_receive_header_key2 = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);

	//creating Alice's identity keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice' identity keypair.");

	//creating Alice's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice' ephemeral keypair.");

	//creating Bob's identity keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			bob_string,
			identity_string);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's identity keypair.");

	//creating Bob's ephemeral keypair
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			bob_string,
			ephemeral_string);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's ephemeral keypair.");

	//start new ratchet for alice
	printf("Creating new ratchet for Alice ...\n");
	status = ratchet_create(
			&alice_state,
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	alice_private_ephemeral->clear();
	alice_private_identity->clear();
	THROW_on_error(CREATION_ERROR, "Failed to create Alice' ratchet.");
	putchar('\n');
	//print Alice's initial root and chain keys
	printf("Alice's initial root key (%zu Bytes):\n", alice_state->root_key.content_length);
	print_hex(&alice_state->root_key);
	printf("Alice's initial chain key (%zu Bytes):\n", alice_state->send_chain_key.content_length);
	print_hex(&alice_state->send_chain_key);
	putchar('\n');

	//start new ratchet for bob
	printf("Creating new ratchet for Bob ...\n");
	status = ratchet_create(
			&bob_state,
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	bob_private_identity->clear();
	bob_private_ephemeral->clear();
	THROW_on_error(CREATION_ERROR, "Failed to create Bob's ratchet.");
	putchar('\n');
	//print Bob's initial root and chain keys
	printf("Bob's initial root key (%zu Bytes):\n", bob_state->root_key.content_length);
	print_hex(&bob_state->root_key);
	printf("Bob's initial chain key (%zu Bytes):\n", bob_state->send_chain_key.content_length);
	print_hex(&bob_state->send_chain_key);
	putchar('\n');

	//compare Alice's and Bob's initial root and chain keys
	status_int = alice_state->root_key.compare(&bob_state->root_key);
	if (status_int != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Alice's and Bob's initial root keys arent't the same.");
	}
	printf("Alice's and Bob's initial root keys match!\n");

	//initial chain key
	status_int = alice_state->receive_chain_key.compare(&bob_state->send_chain_key);
	if (status_int != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Alice's and Bob's initial chain keys aren't the same.");
	}
	printf("Alice's and Bob's initial chain keys match!\n\n");

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//first, alice sends two messages
	uint32_t alice_send_message_number1;
	uint32_t alice_previous_message_number1;
	status = ratchet_send(
			alice_state,
			alice_send_header_key1,
			&alice_send_message_number1,
			&alice_previous_message_number1,
			alice_send_ephemeral1,
			alice_send_message_key1);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Alice's first send message key.");
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 1:\n");
	print_hex(alice_send_message_key1);
	printf("Alice Ratchet 1 send header key 1:\n");
	print_hex(alice_send_header_key1);
	putchar('\n');

	//second message key
	uint32_t alice_send_message_number2;
	uint32_t alice_previous_message_number2;
	status = ratchet_send(
			alice_state,
			alice_send_header_key2,
			&alice_send_message_number2,
			&alice_previous_message_number2,
			alice_send_ephemeral2,
			alice_send_message_key2);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Alice's second send message key.");
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 2:\n");
	print_hex(alice_send_message_key2);
	printf("Alice Ratchet 1 send header key 2:\n");
	print_hex(alice_send_header_key2);
	putchar('\n');

	//third message_key
	uint32_t alice_send_message_number3;
	uint32_t alice_previous_message_number3;
	status = ratchet_send(
			alice_state,
			alice_send_header_key3,
			&alice_send_message_number3,
			&alice_previous_message_number3,
			alice_send_ephemeral3,
			alice_send_message_key3);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Alice's third send message key.");
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 3:\n");
	print_hex(alice_send_message_key3);
	printf("Alice Ratchet 1 send header key 3:\n");
	print_hex(alice_send_header_key3);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to bob's receive header keys
	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Bob's receive header keys.");
	}

	printf("Bob's first current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's first next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (bob_current_receive_header_key->compare(alice_send_header_key1) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (bob_next_receive_header_key->compare(alice_send_header_key1) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "Failed to decrypt header.");
	}
	alice_send_header_key1->clear();
	bob_current_receive_header_key->clear();
	bob_next_receive_header_key->clear();

	//now the receive end, Bob recreates the message keys

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			bob_state,
			decryptable);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set Bob's header decryptability.");
	}

	status = ratchet_receive(
			bob_state,
			bob_receive_key1,
			alice_send_ephemeral1,
			0, //purported message number
			0); //purported previous message number
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(RECEIVE_ERROR, "Failed to generate Bob's first receive key.");
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 1:\n");
	print_hex(bob_receive_key1);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set authenticity state.");
	}

	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Bob's header keys.");
	}

	printf("Bob's second current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's second next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (bob_current_receive_header_key->compare(alice_send_header_key2) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (bob_next_receive_header_key->compare(alice_send_header_key2) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "Failed to decrypt header.");
	}
	alice_send_header_key2->clear();
	bob_current_receive_header_key->clear();
	bob_next_receive_header_key->clear();

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			bob_state,
			decryptable);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set header decryptability.");
	}

	//second receive message key
	status = ratchet_receive(
			bob_state,
			bob_receive_key2,
			alice_send_ephemeral2,
			1, //purported message number
			0); //purported previous message number
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(RECEIVE_ERROR, "Failed to generate Bob's second receive key.");
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 2:\n");
	print_hex(bob_receive_key2);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set authenticity state.");
	}

	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get receive header key buffers.");
	}

	printf("Bob's third current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's third next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (bob_current_receive_header_key->compare(alice_send_header_key3) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (bob_next_receive_header_key->compare(alice_send_header_key3) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "Failed to decrypt header.");
	}
	alice_send_header_key3->clear();
	bob_current_receive_header_key->clear();
	bob_next_receive_header_key->clear();

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			bob_state,
			decryptable);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set header decryptability.");
	}

	//third receive message key
	status = ratchet_receive(
			bob_state,
			bob_receive_key3,
			alice_send_ephemeral3,
			2, //purported message number
			0); //purported previous message number
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(RECEIVE_ERROR, "Failed to generate Bob's third receive key.");
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 3:\n");
	print_hex(bob_receive_key3);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set authenticity state.");
	}

	//compare the message keys
	if (alice_send_message_key1->compare(bob_receive_key1) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Alice's first send key and Bob's first receive key aren't the same.");
	}
	alice_send_message_key1->clear();
	bob_receive_key1->clear();
	printf("Alice's first send key and Bob's first receive key match.\n");

	//second key
	if (alice_send_message_key2->compare(bob_receive_key2) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Alice's second send key and Bob's second receive key aren't the same.");
	}
	alice_send_message_key2->clear();
	bob_receive_key2->clear();
	printf("Alice's second send key and Bob's second receive key match.\n");

	//third key
	if (alice_send_message_key3->compare(bob_receive_key3) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Alice's third send key and Bob's third receive key aren't the same.");
	}
	alice_send_message_key3->clear();
	bob_receive_key3->clear();
	printf("Alice's third send key and Bob's third receive key match.\n");
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//Now Bob replies with three messages
	uint32_t bob_send_message_number1;
	uint32_t bob_previous_message_number1;
	status = ratchet_send(
			bob_state,
			bob_send_header_key1,
			&bob_send_message_number1,
			&bob_previous_message_number1,
			bob_send_ephemeral1,
			bob_send_message_key1);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Bob's first send message key.");
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key1);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key1);
	putchar('\n');

	//second message key
	uint32_t bob_send_message_number2;
	uint32_t bob_previous_message_number2;
	status = ratchet_send(
			bob_state,
			bob_send_header_key2,
			&bob_send_message_number2,
			&bob_previous_message_number2,
			bob_send_ephemeral2,
			bob_send_message_key2);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Bob's second send message key.");
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key2);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key2);
	putchar('\n');

	//third message key
	uint32_t bob_send_message_number3;
	uint32_t bob_previous_message_number3;
	status = ratchet_send(
			bob_state,
			bob_send_header_key3,
			&bob_send_message_number3,
			&bob_previous_message_number3,
			bob_send_ephemeral3,
			bob_send_message_key3);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Bob's third send message key.");
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 3:\n");
	print_hex(bob_send_message_key3);
	printf("Bob Ratchet 2 send header key 3:\n");
	print_hex(bob_send_header_key3);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to alice's receive header keys
	status = ratchet_get_receive_header_keys(
			alice_current_receive_header_key,
			alice_next_receive_header_key,
			alice_state);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Alice' receive keys.");
	}

	printf("Alice's first current receive header key:\n");
	print_hex(alice_current_receive_header_key);
	printf("Alice's first next receive_header_key:\n");
	print_hex(alice_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (alice_current_receive_header_key->compare(bob_send_header_key1) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (alice_next_receive_header_key->compare(bob_send_header_key1) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "Failed to decrypt header.");
	}
	bob_send_header_key1->clear();
	alice_current_receive_header_key->clear();
	alice_next_receive_header_key->clear();

	//now alice receives the first, then the third message (second message skipped)

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			alice_state,
			decryptable);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set header decryptability.");
	}

	status = ratchet_receive(
			alice_state,
			alice_receive_message_key1,
			bob_send_ephemeral1,
			0, //purported message number
			0); //purported previous message number
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(RECEIVE_ERROR, "Failed to generate Alice's first receive key.");
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 1:\n");
	print_hex(alice_receive_message_key1);
	putchar('\n');

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set authenticity state.");
	}

	status = ratchet_get_receive_header_keys(
			alice_current_receive_header_key,
			alice_next_receive_header_key,
			alice_state);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_FETCH_ERROR, "Failed to get Alice' receive header keys.");
	}

	printf("Alice's current receive header key:\n");
	print_hex(alice_current_receive_header_key);
	printf("Alice's next receive_header_key:\n");
	print_hex(alice_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (alice_current_receive_header_key->compare(bob_send_header_key3) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (alice_next_receive_header_key->compare(bob_send_header_key3) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "Failed to decrypt header.");
	}
	bob_send_header_key3->clear();
	alice_current_receive_header_key->clear();
	alice_next_receive_header_key->clear();

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			alice_state,
			decryptable);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set header decryptability.");
	}

	//third received message key (second message skipped)
	status = ratchet_receive(
			alice_state,
			alice_receive_message_key3,
			bob_send_ephemeral3,
			2,
			0);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(RECEIVE_ERROR, "Faield to generate Alice's third receive key.");
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 3:\n");
	print_hex(alice_receive_message_key3);
	putchar('\n');

	assert(alice_state->staged_header_and_message_keys.length == 1);

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	on_error {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(DATA_SET_ERROR, "Failed to set authenticity state.");
	}

	assert(alice_state->staged_header_and_message_keys.length == 0);
	assert(alice_state->skipped_header_and_message_keys.length == 1);

	//get the second receive message key from the message and header keystore
	status_int = alice_receive_message_key2->cloneFrom(alice_state->skipped_header_and_message_keys.tail->message_key);
	if (status_int != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(BUFFER_ERROR, "Failed to get Alice's second receive message key.");
	}
	printf("Alice Ratchet 2 receive message key 2:\n");
	print_hex(alice_receive_message_key2);
	putchar('\n');

	//get the second receive header key from the message and header keystore
	status_int = alice_receive_header_key2->cloneFrom(alice_state->skipped_header_and_message_keys.tail->header_key);
	if (status_int != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(BUFFER_ERROR, "Failed to get Alice's second receive header key.");
	}
	printf("Alice Ratchet 2 receive header key 2:\n");
	print_hex(alice_receive_header_key2);
	putchar('\n');

	//compare header keys
	if (alice_receive_header_key2->compare(bob_send_header_key2) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Bob's second send header key and Alice's receive header key aren't the same.");
	}
	printf("Bob's second send header key and Alice's receive header keys match.\n");
	alice_receive_header_key2->clear();
	bob_send_header_key2->clear();

	//compare the keys
	if (bob_send_message_key1->compare(alice_receive_message_key1) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Bob's first send key and Alice's first receive key aren't the same.");
	}
	bob_send_message_key1->clear();
	bob_send_message_key1->clear();
	printf("Bob's first send key and Alice's first receive key match.\n");

	//second key
	if (bob_send_message_key2->compare(alice_receive_message_key2) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Bob's second send key and Alice's second receive key aren't the same.");
	}
	bob_send_message_key2->clear();
	alice_receive_message_key2->clear();
	printf("Bob's second send key and Alice's second receive key match.\n");

	//third key
	if (bob_send_message_key3->compare(alice_receive_message_key3) != 0) {
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		THROW(INCORRECT_DATA, "Bob's third send key and Alice's third receive key aren't the same.");
	}
	bob_send_message_key3->clear();
	alice_receive_message_key3->clear();
	printf("Bob's third send key and Alice's third receive key match.\n\n");


	//export Alice's ratchet to Protobuf-C
	printf("Export to Protobuf-C!\n");
	status = protobuf_export(alice_state, &protobuf_export_buffer);
	THROW_on_error(EXPORT_ERROR, "Failed to export Alice' ratchet to protobuf-c.");

	print_hex(protobuf_export_buffer);
	puts("\n\n");

	ratchet_destroy(alice_state);
	alice_state = nullptr;

	//import again
	printf("Import from Protobuf-C!\n");
	status = protobuf_import(
		&alice_state,
		protobuf_export_buffer);
	THROW_on_error(IMPORT_ERROR, "Failed to import Alice' ratchet from Protobuf-C.");

	//export again
	status = protobuf_export(alice_state, &protobuf_second_export_buffer);
	THROW_on_error(EXPORT_ERROR, "Failed to export Alice' ratchet to protobuf-c the second time.");

	//compare both exports
	if ((protobuf_export_buffer == NULL) || (protobuf_export_buffer->compare(protobuf_second_export_buffer) != 0)) {
		print_hex(protobuf_second_export_buffer);
		THROW(INCORRECT_DATA, "Both exports don't match!");
	}
	printf("Exported Protobuf-C buffers match!\n");

	//destroy the ratchets again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);
	printf("Destroying Bob's ratchet ...\n");
	ratchet_destroy(bob_state);

cleanup:
	//export buffers
	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_buffer);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_buffer);

	//create all the buffers
	//alice keys
	buffer_destroy_from_heap_and_null_if_valid(alice_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(alice_public_ephemeral);
	//bob keys
	buffer_destroy_from_heap_and_null_if_valid(bob_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_ephemeral);
	//alice send message and header keys
	buffer_destroy_from_heap_and_null_if_valid(alice_send_message_key1);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_header_key1);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_ephemeral1);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_message_key2);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_header_key2);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_ephemeral2);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_message_key3);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_header_key3);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_ephemeral3);
	//bobs receive keys
	buffer_destroy_from_heap_and_null_if_valid(bob_current_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_next_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_key1);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_key2);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_key3);
	//bobs śend message and header keys
	buffer_destroy_from_heap_and_null_if_valid(bob_send_message_key1);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_header_key1);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_ephemeral1);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_message_key2);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_header_key2);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_ephemeral2);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_message_key3);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_header_key3);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_ephemeral3);
	//alice receive keys
	buffer_destroy_from_heap_and_null_if_valid(alice_current_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_next_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_message_key1);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_message_key2);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_message_key3);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_header_key2);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
