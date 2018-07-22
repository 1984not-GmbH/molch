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

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//create keys
		//alice
		//identity
		PrivateKey alice_private_identity;
		PublicKey alice_public_identity;
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//bob
		//identity
		PrivateKey bob_private_identity;
		PublicKey bob_public_identity;
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//get the prekey list
		Buffer prekey_list{PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE};
		PrekeyStore bob_prekeys;
		bob_prekeys.list(prekey_list);

		//start a send conversation
		Buffer send_message{"Hello there!"};
		Buffer packet;
		Molch::Conversation alice_send_conversation(
				send_message,
				packet,
				alice_public_identity,
				alice_private_identity,
				bob_public_identity,
				prekey_list);

		printf("Packet:\n");
		packet.printHex(std::cout) << std::endl;

		//let bob receive the packet
		Buffer received_message;
		Molch::Conversation bob_receive_conversation{
			packet,
			received_message,
			bob_public_identity,
			bob_private_identity,
			bob_prekeys};

		if (send_message != received_message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Message was decrypted incorrectly."};
		}
		printf("Decrypted message matches with the original message.\n");

		//send and receive some more messages
		//first one
		Buffer alice_send_message2{"How are you Bob?"};
		TRY_WITH_RESULT(alice_send_packet2_result, alice_send_conversation.send(alice_send_message2, std::nullopt));
		auto& alice_send_packet2{alice_send_packet2_result.value()};

		printf("Sent message: %.*s\n", static_cast<int>(alice_send_message2.size()), reinterpret_cast<const char*>(alice_send_message2.data()));
		printf("Packet:\n");
		alice_send_packet2.printHex(std::cout) << std::endl;

		//bob receives the message
		TRY_WITH_RESULT(bob_received2_result, bob_receive_conversation.receive(alice_send_packet2));
		const auto& bob_received2{bob_received2_result.value()};

		// check the message numbers
		if ((bob_received2.message_number != 1) || (bob_received2.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message number for Bob."};
		}

		//now check if the received message was correctly decrypted
		if (bob_received2.message != alice_send_message2) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received message doesn't match."};
		}
		printf("Alice' second message has been sent correctly!\n");

		//Bob responds to alice
		Buffer bob_response_message{"I'm fine, thanks. How are you?"};
		TRY_WITH_RESULT(bob_response_packet_result, bob_receive_conversation.send(bob_response_message, std::nullopt));
		auto& bob_response_packet{bob_response_packet_result.value()};

		printf("Sent message: %.*s\n", static_cast<int>(bob_response_message.size()), reinterpret_cast<const char*>(bob_response_message.data()));
		printf("Packet:\n");
		bob_response_packet.printHex(std::cout) << std::endl;

		//Alice receives the response
		TRY_WITH_RESULT(alice_received_result, alice_send_conversation.receive(bob_response_packet));
		const auto& alice_received{alice_received_result.value()};

		// check the message numbers
		if ((alice_received.message_number != 0) || (alice_received.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message number for Alice."};
		}

		//compare sent and received messages
		if (bob_response_message != alice_received.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received response doesn't match."};
		}
		printf("Successfully received Bob's response!\n");

		//---------------------------------------------------------------------------------------------
		//now test it the other way round (because Axolotl is assymetric in this regard)
		//Bob sends the message to Alice.

		//get alice prekey list
		PrekeyStore alice_prekeys;
		alice_prekeys.list(prekey_list);

		//destroy the old packet
		packet.clear();
		Molch::Conversation bob_send_conversation{
			send_message,
			packet,
			bob_public_identity,
			bob_private_identity,
			alice_public_identity,
			prekey_list};

		printf("Sent message: %.*s\n", static_cast<int>(send_message.size()), reinterpret_cast<const char*>(send_message.data()));
		printf("Packet:\n");
		packet.printHex(std::cout) << std::endl;

		//let alice receive the packet
		received_message.clear();
		Molch::Conversation alice_receive_conversation{
			packet,
			received_message,
			alice_public_identity,
			alice_private_identity,
			alice_prekeys};

		if (send_message != received_message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Message incorrectly decrypted."};
		}
		printf("Decrypted message matched with the original message.\n");

		//send and receive some more messages
		//first one
		Buffer bob_send_message2{"How are you Alice?"};
		TRY_WITH_RESULT(bob_send_packet2_result, bob_send_conversation.send(bob_send_message2, std::nullopt));
		auto& bob_send_packet2{bob_send_packet2_result.value()};

		printf("Sent message: %.*s\n", static_cast<int>(bob_send_message2.size()), reinterpret_cast<const char*>(bob_send_message2.data()));
		printf("Packet:\n");
		bob_send_packet2.printHex(std::cout) << std::endl;

		//alice receives the message
		TRY_WITH_RESULT(alice_received2_result, alice_receive_conversation.receive(bob_send_packet2));
		const auto& alice_received2{alice_received2_result.value()};

		// check message numbers
		if ((alice_received2.message_number != 1) || (alice_received2.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message numbers for Alice."};
		}

		//now check if the received message was correctly decrypted
		if (alice_received2.message != bob_send_message2) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received message doesn't match."};
		}
		printf("Bobs second message has been sent correctly!.\n");

		//Alice responds to Bob
		Buffer alice_response_message{"I'm fine, thanks. How are you?"};
		TRY_WITH_RESULT(alice_response_packet_result, alice_receive_conversation.send(alice_response_message, std::nullopt));
		auto& alice_response_packet{alice_response_packet_result.value()};

		printf("Sent message: %.*s\n", static_cast<int>(alice_response_message.size()), reinterpret_cast<const char*>(alice_response_message.data()));
		printf("Packet:\n");
		alice_response_packet.printHex(std::cout) << std::endl;

		//Bob receives the response
		TRY_WITH_RESULT(bob_received_response_result, bob_send_conversation.receive(alice_response_packet));
		const auto& bob_received_response{bob_received_response_result.value()};

		// check message numbers
		if ((bob_received_response.message_number != 0) || (bob_received_response.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message numbers for Alice."};
		}

		//compare sent and received messages
		if (alice_response_message != bob_received_response.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received response doesn't match."};
		}
		printf("Successfully received Alice' response!\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
