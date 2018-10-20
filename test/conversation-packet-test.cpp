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
#include "inline-utils.hpp"
#include "exception.hpp"
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
		TRY_WITH_RESULT(bob_prekeys_result, PrekeyStore::create());
		auto& bob_prekeys{bob_prekeys_result.value()};
		TRY_WITH_RESULT(bob_prekey_list_result, bob_prekeys.list());
		const auto& bob_prekey_list{bob_prekey_list_result.value()};

		//start a send conversation
		Buffer send_message{"Hello there!"};
		TRY_WITH_RESULT(alice_send_conversation_result, Molch::Conversation::createSendConversation(
				send_message,
				alice_public_identity,
				alice_private_identity,
				bob_public_identity,
				bob_prekey_list));
		auto& alice_send_conversation{alice_send_conversation_result.value()};

		std::cout << "Packet:\n";
		std::cout << alice_send_conversation.packet << std::endl;

		//let bob receive the packet
		TRY_WITH_RESULT(bob_receive_conversation_result, Molch::Conversation::createReceiveConversation(
			alice_send_conversation.packet,
			bob_public_identity,
			bob_private_identity,
			bob_prekeys));
		auto& bob_receive_conversation{bob_receive_conversation_result.value()};

		if (send_message != bob_receive_conversation.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Message was decrypted incorrectly."};
		}
		std::cout << "Decrypted message matches with the original message.\n";

		//send and receive some more messages
		//first one
		Buffer alice_send_message2{"How are you Bob?"};
		TRY_WITH_RESULT(alice_send_packet2_result, alice_send_conversation.conversation.send(alice_send_message2, std::nullopt));
		auto& alice_send_packet2{alice_send_packet2_result.value()};

		std::cout << "Sent message: " << std::string_view(byte_to_char(alice_send_message2.data()), alice_send_message2.size()) << '\n';
		std::cout << "Packet:\n";
		std::cout << alice_send_packet2 << std::endl;

		//bob receives the message
		TRY_WITH_RESULT(bob_received2_result, bob_receive_conversation.conversation.receive(alice_send_packet2));
		const auto& bob_received2{bob_received2_result.value()};

		// check the message numbers
		if ((bob_received2.message_number != 1) || (bob_received2.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message number for Bob."};
		}

		//now check if the received message was correctly decrypted
		if (bob_received2.message != alice_send_message2) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received message doesn't match."};
		}
		std::cout << "Alice' second message has been sent correctly!\n";

		//Bob responds to alice
		Buffer bob_response_message{"I'm fine, thanks. How are you?"};
		TRY_WITH_RESULT(bob_response_packet_result, bob_receive_conversation.conversation.send(bob_response_message, std::nullopt));
		auto& bob_response_packet{bob_response_packet_result.value()};

		std::cout << "Sent message: " << std::string_view(byte_to_char(bob_response_message.data()), bob_response_message.size()) << '\n';
		std::cout << "Packet:\n";
		std::cout << bob_response_packet << std::endl;

		//Alice receives the response
		TRY_WITH_RESULT(alice_received_result, alice_send_conversation.conversation.receive(bob_response_packet));
		const auto& alice_received{alice_received_result.value()};

		// check the message numbers
		if ((alice_received.message_number != 0) || (alice_received.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message number for Alice."};
		}

		//compare sent and received messages
		if (bob_response_message != alice_received.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received response doesn't match."};
		}
		std::cout << "Successfully received Bob's response!\n";

		//---------------------------------------------------------------------------------------------
		//now test it the other way round (because Axolotl is assymetric in this regard)
		//Bob sends the message to Alice.

		//get alice prekey list
		TRY_WITH_RESULT(alice_prekeys_result, PrekeyStore::create());
		auto& alice_prekeys{alice_prekeys_result.value()};
		TRY_WITH_RESULT(alice_prekey_list_result, alice_prekeys.list());
		const auto& alice_prekey_list{alice_prekey_list_result.value()};

		//destroy the old packet
		TRY_WITH_RESULT(bob_send_conversation_result, Molch::Conversation::createSendConversation(
			send_message,
			bob_public_identity,
			bob_private_identity,
			alice_public_identity,
			alice_prekey_list));
		auto& bob_send_conversation{bob_send_conversation_result.value()};

		std::cout << "Sent message: " << std::string_view(byte_to_char(send_message.data()), send_message.size()) << '\n';
		std::cout << "Packet:\n";
		std::cout << bob_send_conversation.packet << std::endl;

		//let alice receive the packet
		TRY_WITH_RESULT(alice_receive_conversation_result, Molch::Conversation::createReceiveConversation(
			bob_send_conversation.packet,
			alice_public_identity,
			alice_private_identity,
			alice_prekeys));
		auto& alice_receive_conversation{alice_receive_conversation_result.value()};

		if (send_message != alice_receive_conversation.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Message incorrectly decrypted."};
		}
		std::cout << "Decrypted message matched with the original message.\n";

		//send and receive some more messages
		//first one
		Buffer bob_send_message2{"How are you Alice?"};
		TRY_WITH_RESULT(bob_send_packet2_result, bob_send_conversation.conversation.send(bob_send_message2, std::nullopt));
		auto& bob_send_packet2{bob_send_packet2_result.value()};

		std::cout << "Sent message: " << std::string_view(byte_to_char(bob_send_message2.data()), bob_send_message2.size()) << '\n';
		std::cout << "Packet:\n";
		std::cout << bob_send_packet2 << std::endl;

		//alice receives the message
		TRY_WITH_RESULT(alice_received2_result, alice_receive_conversation.conversation.receive(bob_send_packet2));
		const auto& alice_received2{alice_received2_result.value()};

		// check message numbers
		if ((alice_received2.message_number != 1) || (alice_received2.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message numbers for Alice."};
		}

		//now check if the received message was correctly decrypted
		if (alice_received2.message != bob_send_message2) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received message doesn't match."};
		}
		std::cout << "Bobs second message has been sent correctly!.\n";

		//Alice responds to Bob
		Buffer alice_response_message{"I'm fine, thanks. How are you?"};
		TRY_WITH_RESULT(alice_response_packet_result, alice_receive_conversation.conversation.send(alice_response_message, std::nullopt));
		auto& alice_response_packet{alice_response_packet_result.value()};

		std::cout << "Sent message: " << std::string_view(byte_to_char(alice_response_message.data()), alice_response_message.size()) << '\n';
		std::cout << "Packet:\n";
		std::cout << alice_response_packet << std::endl;

		//Bob receives the response
		TRY_WITH_RESULT(bob_received_response_result, bob_send_conversation.conversation.receive(alice_response_packet));
		const auto& bob_received_response{bob_received_response_result.value()};

		// check message numbers
		if ((bob_received_response.message_number != 0) || (bob_received_response.previous_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message numbers for Alice."};
		}

		//compare sent and received messages
		if (alice_response_message != bob_received_response.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Received response doesn't match."};
		}
		std::cout << "Successfully received Alice' response!\n";
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
