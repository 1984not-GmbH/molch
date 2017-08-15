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
#include <exception>
#include <iostream>

#include "common.hpp"
#include "utils.hpp"
#include "../lib/conversation.hpp"
#include "../lib/molch-exception.hpp"

int main(void) {
	try {
		if (sodium_init() != 0) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium!");
		}

		//create keys
		//alice
		//identity
		Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		exception_on_invalid_buffer(alice_private_identity);
		exception_on_invalid_buffer(alice_public_identity);
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//bob
		//identity
		Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		exception_on_invalid_buffer(bob_private_identity);
		exception_on_invalid_buffer(bob_public_identity);
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//get the prekey list
		Buffer prekey_list(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);
		exception_on_invalid_buffer(prekey_list);
		PrekeyStore bob_prekeys;
		bob_prekeys.list(prekey_list);

		//start a send conversation
		Buffer send_message("Hello there!");
		std::unique_ptr<Buffer> packet;
		ConversationT alice_send_conversation(
				send_message,
				packet,
				alice_public_identity,
				alice_private_identity,
				bob_public_identity,
				prekey_list);

		printf("Packet:\n");
		std::cout << packet->toHex();
		putchar('\n');

		//let bob receive the packet
		std::unique_ptr<Buffer> received_message;
		ConversationT bob_receive_conversation(
				*packet,
				received_message,
				bob_public_identity,
				bob_private_identity,
				bob_prekeys);

		if (send_message != *received_message) {
			throw MolchException(INVALID_VALUE, "Message was decrypted incorrectly.");
		}
		printf("Decrypted message matches with the original message.\n");

		//send and receive some more messages
		//first one
		Buffer alice_send_message2("How are you Bob?");
		auto alice_send_packet2 = alice_send_conversation.send(
				alice_send_message2,
				nullptr,
				nullptr,
				nullptr);

		printf("Sent message: %.*s\n", static_cast<int>(alice_send_message2.content_length), reinterpret_cast<const char*>(alice_send_message2.content));
		printf("Packet:\n");
		std::cout << alice_send_packet2->toHex();
		putchar('\n');

		//bob receives the message
		uint32_t bob_receive_message_number = UINT32_MAX;
		uint32_t bob_previous_receive_message_number = UINT32_MAX;
		auto bob_receive_message2 = bob_receive_conversation.receive(
				*alice_send_packet2,
				bob_receive_message_number,
				bob_previous_receive_message_number);

		// check the message numbers
		if ((bob_receive_message_number != 1) || (bob_previous_receive_message_number != 0)) {
			throw MolchException(INCORRECT_DATA, "Incorrect receive message number for Bob.");
		}

		//now check if the received message was correctly decrypted
		if (*bob_receive_message2 != alice_send_message2) {
			throw MolchException(INVALID_VALUE, "Received message doesn't match.");
		}
		printf("Alice' second message has been sent correctly!\n");

		//Bob responds to alice
		Buffer bob_response_message("I'm fine, thanks. How are you?");
		auto bob_response_packet = bob_receive_conversation.send(
				bob_response_message,
				nullptr,
				nullptr,
				nullptr);

		printf("Sent message: %.*s\n", static_cast<int>(bob_response_message.content_length), reinterpret_cast<const char*>(bob_response_message.content));
		printf("Packet:\n");
		std::cout << bob_response_packet->toHex();
		putchar('\n');

		//Alice receives the response
		uint32_t alice_receive_message_number = UINT32_MAX;
		uint32_t alice_previous_receive_message_number = UINT32_MAX;
		auto alice_received_response = alice_send_conversation.receive(
				*bob_response_packet,
				alice_receive_message_number,
				alice_previous_receive_message_number);

		// check the message numbers
		if ((alice_receive_message_number != 0) || (alice_previous_receive_message_number != 0)) {
			throw MolchException(INCORRECT_DATA, "Incorrect receive message number for Alice.");
		}

		//compare sent and received messages
		if (bob_response_message != *alice_received_response) {
			throw MolchException(INVALID_VALUE, "Received response doesn't match.");
		}
		printf("Successfully received Bob's response!\n");

		//---------------------------------------------------------------------------------------------
		//now test it the other way round (because Axolotl is assymetric in this regard)
		//Bob sends the message to Alice.

		//get alice prekey list
		PrekeyStore alice_prekeys;
		alice_prekeys.list(prekey_list);

		//destroy the old packet
		packet.reset();
		ConversationT bob_send_conversation(
				send_message,
				packet,
				bob_public_identity,
				bob_private_identity,
				alice_public_identity,
				prekey_list);

		printf("Sent message: %.*s\n", static_cast<int>(send_message.content_length), reinterpret_cast<const char*>(send_message.content));
		printf("Packet:\n");
		std::cout << packet->toHex();
		putchar('\n');

		//let alice receive the packet
		received_message.reset();
		ConversationT alice_receive_conversation(
				*packet,
				received_message,
				alice_public_identity,
				alice_private_identity,
				alice_prekeys);

		if (send_message != *received_message) {
			throw MolchException(INVALID_VALUE, "Message incorrectly decrypted.");
		}
		printf("Decrypted message matched with the original message.\n");

		//send and receive some more messages
		//first one
		Buffer bob_send_message2("How are you Alice?");
		auto bob_send_packet2 = bob_send_conversation.send(
				bob_send_message2,
				nullptr,
				nullptr,
				nullptr);

		printf("Sent message: %.*s\n", static_cast<int>(bob_send_message2.content_length), reinterpret_cast<const char*>(bob_send_message2.content));
		printf("Packet:\n");
		std::cout << bob_send_packet2->toHex();
		putchar('\n');

		//alice receives the message
		auto alice_receive_message2 = alice_receive_conversation.receive(
				*bob_send_packet2,
				alice_receive_message_number,
				alice_previous_receive_message_number);

		// check message numbers
		if ((alice_receive_message_number != 1) || (alice_previous_receive_message_number != 0)) {
			throw MolchException(INCORRECT_DATA, "Incorrect receive message numbers for Alice.");
		}

		//now check if the received message was correctly decrypted
		if (*alice_receive_message2 != bob_send_message2) {
			throw MolchException(INVALID_VALUE, "Received message doesn't match.");
		}
		printf("Bobs second message has been sent correctly!.\n");

		//Alice responds to Bob
		Buffer alice_response_message("I'm fine, thanks. How are you?");
		auto alice_response_packet = alice_receive_conversation.send(
				alice_response_message,
				nullptr,
				nullptr,
				nullptr);

		printf("Sent message: %.*s\n", static_cast<int>(alice_response_message.content_length), reinterpret_cast<const char*>(alice_response_message.content));
		printf("Packet:\n");
		std::cout << alice_response_packet->toHex();
		putchar('\n');

		//Bob receives the response
		auto bob_received_response = bob_send_conversation.receive(
				*alice_response_packet,
				bob_receive_message_number,
				bob_previous_receive_message_number);

		// check message numbers
		if ((bob_receive_message_number != 0) || (bob_previous_receive_message_number != 0)) {
			throw MolchException(INCORRECT_DATA, "Incorrect receive message numbers for Alice.");
		}

		//compare sent and received messages
		if (alice_response_message != *bob_received_response) {
			throw MolchException(INVALID_VALUE, "Received response doesn't match.");
		}
		printf("Successfully received Alice' response!\n");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
	}
}
