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

#include "common.h"
#include "utils.h"
#include "../lib/conversation.h"

int main(void) noexcept {
	//create buffers
	//alice' keys
	Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//bobs keys
	Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	Buffer *packet = nullptr;
	Buffer *received_message = nullptr;

	//packets
	Buffer *alice_send_packet2 = nullptr;
	Buffer *bob_send_packet2 = nullptr;
	Buffer *bob_response_packet = nullptr;
	Buffer *alice_response_packet = nullptr;

	//receive messages
	Buffer *alice_receive_message2 = nullptr;
	Buffer *bob_receive_message2 = nullptr;
	Buffer *alice_received_response = nullptr;
	Buffer *bob_received_response = nullptr;

	//create prekey stores
	PrekeyStore *alice_prekeys = nullptr;
	PrekeyStore *bob_prekeys = nullptr;

	Buffer prekey_list(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);

	//conversations
	conversation_t *alice_send_conversation = nullptr;
	conversation_t *alice_receive_conversation = nullptr;
	conversation_t *bob_send_conversation = nullptr;
	conversation_t *bob_receive_conversation = nullptr;

	//message numbers
	uint32_t alice_receive_message_number = UINT32_MAX;
	uint32_t alice_previous_receive_message_number = UINT32_MAX;
	uint32_t bob_receive_message_number = UINT32_MAX;
	uint32_t bob_previous_receive_message_number = UINT32_MAX;
	Buffer send_message("Hello there!");

	return_status status = return_status_init();
	int status_int = sodium_init();
	if (status_int != 0) {
		THROW(INIT_ERROR, "Failed to initialize libsodium!");
	}
	throw_on_invalid_buffer(alice_private_identity);
	throw_on_invalid_buffer(alice_public_identity);
	throw_on_invalid_buffer(bob_private_identity);
	throw_on_invalid_buffer(bob_public_identity);
	throw_on_invalid_buffer(prekey_list);

	//create prekey stores
	status = PrekeyStore::create(alice_prekeys);
	THROW_on_error(CREATION_ERROR, "Failed to create Alice' prekey store.");
	status = PrekeyStore::create(bob_prekeys);
	THROW_on_error(CREATION_ERROR, "Failed to create Bobs prekey store.");

	//create keys
	//alice
	//identity
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate Alice' identity keys.");

	//bob
	//identity
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate Bob's identity keys.");

	//get the prekey list
	status = bob_prekeys->list(prekey_list);
	THROW_on_error(GENERIC_ERROR, "Failed to get Bob's prekey list.");

	//start a send conversation
	status = conversation_start_send_conversation(
			&alice_send_conversation,
			&send_message,
			&packet,
			&alice_public_identity,
			&alice_private_identity,
			&bob_public_identity,
			&prekey_list);
	THROW_on_error(SEND_ERROR, "Failed to send message.");

	printf("Packet:\n");
	print_hex(*packet);
	putchar('\n');

	//let bob receive the packet
	status = conversation_start_receive_conversation(
			&bob_receive_conversation,
			packet,
			&received_message,
			&bob_public_identity,
			&bob_private_identity,
			bob_prekeys);
	THROW_on_error(RECEIVE_ERROR, "Failed to decrypt received message.");

	status_int = send_message.compare(received_message);
	if (status_int != 0) {
		THROW(INVALID_VALUE, "Message was decrypted incorrectly.");
	}
	printf("Decrypted message matches with the original message.\n");

	//send and receive some more messages
	//first one
	{
		Buffer alice_send_message2("How are you Bob?");
		status = conversation_send(
				alice_send_conversation,
				&alice_send_message2,
				&alice_send_packet2,
				nullptr,
				nullptr,
				nullptr);
		THROW_on_error(SEND_ERROR, "Failed to send Alice' second message.");

		printf("Sent message: %.*s\n", (int)alice_send_message2.content_length, (const char*)alice_send_message2.content);
		printf("Packet:\n");
		print_hex(*alice_send_packet2);
		putchar('\n');

		//bob receives the message
		status = conversation_receive(
				bob_receive_conversation,
				alice_send_packet2,
				&bob_receive_message_number,
				&bob_previous_receive_message_number,
				&bob_receive_message2);
		THROW_on_error(RECEIVE_ERROR, "Second message from Alice failed to decrypt.");

		// check the message numbers
		if ((bob_receive_message_number != 1) || (bob_previous_receive_message_number != 0)) {
			THROW(INCORRECT_DATA, "Incorrect receive message number for Bob.");
		}

		//now check if the received message was correctly decrypted
		status_int = bob_receive_message2->compare(&alice_send_message2);
		if (status_int != 0) {
			THROW(INVALID_VALUE, "Received message doesn't match.");
		}
		printf("Alice' second message has been sent correctly!\n");
	}

	//Bob responds to alice
	{
		Buffer bob_response_message("I'm fine, thanks. How are you?");
		status = conversation_send(
				bob_receive_conversation,
				&bob_response_message,
				&bob_response_packet,
				nullptr,
				nullptr,
				nullptr);
		THROW_on_error(SEND_ERROR, "Failed to send Bob's response message.");

		printf("Sent message: %.*s\n", (int)bob_response_message.content_length, (const char*)bob_response_message.content);
		printf("Packet:\n");
		print_hex(*bob_response_packet);
		putchar('\n');

		//Alice receives the response
		status = conversation_receive(
				alice_send_conversation,
				bob_response_packet,
				&alice_receive_message_number,
				&alice_previous_receive_message_number,
				&alice_received_response);
		THROW_on_error(RECEIVE_ERROR, "Response from Bob failed to decrypt.");

		// check the message numbers
		if ((alice_receive_message_number != 0) || (alice_previous_receive_message_number != 0)) {
			THROW(INCORRECT_DATA, "Incorrect receive message number for Alice.");
		}

		//compare sent and received messages
		status_int = bob_response_message.compare(alice_received_response);
		if (status_int != 0) {
			THROW(INVALID_VALUE, "Received response doesn't match.");
		}
		printf("Successfully received Bob's response!\n");
	}

	//---------------------------------------------------------------------------------------------
	//now test it the other way round (because Axolotl is assymetric in this regard)
	//Bob sends the message to Alice.

	//get alice prekey list
	status = alice_prekeys->list(prekey_list);
	THROW_on_error(GENERIC_ERROR, "Failed to get Alice' prekey list.");

	//destroy the old packet
	buffer_destroy_from_heap_and_null_if_valid(packet);
	status = conversation_start_send_conversation(
			&bob_send_conversation,
			&send_message,
			&packet,
			&bob_public_identity,
			&bob_private_identity,
			&alice_public_identity,
			&prekey_list);
	THROW_on_error(SEND_ERROR, "Failed to send message.");

	printf("Sent message: %.*s\n", (int)send_message.content_length, (const char*)send_message.content);
	printf("Packet:\n");
	print_hex(*packet);
	putchar('\n');

	//let alice receive the packet
	buffer_destroy_from_heap_and_null_if_valid(received_message);
	received_message = nullptr;
	status = conversation_start_receive_conversation(
			&alice_receive_conversation,
			packet,
			&received_message,
			&alice_public_identity,
			&alice_private_identity,
			alice_prekeys);
	THROW_on_error(RECEIVE_ERROR, "Failed to decrypt received message.");

	status_int = send_message.compare(received_message);
	if (status_int != 0) {
		THROW(INVALID_VALUE, "Message incorrectly decrypted.");
	}
	printf("Decrypted message matched with the original message.\n");

	//send and receive some more messages
	//first one
	{
		Buffer bob_send_message2("How are you Alice?");
		status = conversation_send(
				bob_send_conversation,
				&bob_send_message2,
				&bob_send_packet2,
				nullptr,
				nullptr,
				nullptr);
		THROW_on_error(SEND_ERROR, "Failed to send Bob's second message.");

		printf("Sent message: %.*s\n", (int)bob_send_message2.content_length, (const char*)bob_send_message2.content);
		printf("Packet:\n");
		print_hex(*bob_send_packet2);
		putchar('\n');

		//alice receives the message
		status = conversation_receive(
				alice_receive_conversation,
				bob_send_packet2,
				&alice_receive_message_number,
				&alice_previous_receive_message_number,
				&alice_receive_message2);
		THROW_on_error(RECEIVE_ERROR, "Second message from Bob failed to decrypt.");

		// check message numbers
		if ((alice_receive_message_number != 1) || (alice_previous_receive_message_number != 0)) {
			THROW(INCORRECT_DATA, "Incorrect receive message numbers for Alice.");
		}

		//now check if the received message was correctly decrypted
		status_int = alice_receive_message2->compare(&bob_send_message2);
		if (status_int != 0) {
			THROW(INVALID_VALUE, "Received message doesn't match.");
		}
		printf("Bobs second message has been sent correctly!.\n");
	}

	//Alice responds to Bob
	{
		Buffer alice_response_message("I'm fine, thanks. How are you?");
		status = conversation_send(
				alice_receive_conversation,
				&alice_response_message,
				&alice_response_packet,
				nullptr,
				nullptr,
				nullptr);
		THROW_on_error(SEND_ERROR, "Failed to send Alice' response message.");

		printf("Sent message: %.*s\n", (int)alice_response_message.content_length, (const char*)alice_response_message.content);
		printf("Packet:\n");
		print_hex(*alice_response_packet);
		putchar('\n');

		//Bob receives the response
		status = conversation_receive(
				bob_send_conversation,
				alice_response_packet,
				&bob_receive_message_number,
				&bob_previous_receive_message_number,
				&bob_received_response);
		THROW_on_error(RECEIVE_ERROR, "Response from Alice failed to decrypt.");

		// check message numbers
		if ((bob_receive_message_number != 0) || (bob_previous_receive_message_number != 0)) {
			THROW(INCORRECT_DATA, "Incorrect receive message numbers for Alice.");
		}

		//compare sent and received messages
		status_int = alice_response_message.compare(bob_received_response);
		if (status_int != 0) {
			THROW(INVALID_VALUE, "Received response doesn't match.");
		}
		printf("Successfully received Alice' response!\n");
	}

cleanup:
	if (alice_prekeys != nullptr) {
		alice_prekeys->destroy();
	}
	if (bob_prekeys != nullptr) {
		bob_prekeys->destroy();
	}
	buffer_destroy_from_heap_and_null_if_valid(packet);
	buffer_destroy_from_heap_and_null_if_valid(received_message);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_packet2);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_message2);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_packet2);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_message2);
	buffer_destroy_from_heap_and_null_if_valid(bob_response_packet);
	buffer_destroy_from_heap_and_null_if_valid(alice_received_response);
	buffer_destroy_from_heap_and_null_if_valid(alice_response_packet);
	buffer_destroy_from_heap_and_null_if_valid(bob_received_response);
	if (alice_send_conversation != nullptr) {
		conversation_destroy(alice_send_conversation);
	}
	if (alice_receive_conversation != nullptr) {
		conversation_destroy(alice_receive_conversation);
	}
	if (bob_send_conversation != nullptr) {
		conversation_destroy(bob_send_conversation);
	}
	if (bob_receive_conversation != nullptr) {
		conversation_destroy(bob_receive_conversation);
	}

	on_error {
		print_errors(status);
		return_status_destroy_errors(&status);
	}

	return status.status;
}
