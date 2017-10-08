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
#include <algorithm>
#include <exception>
#include <iostream>

#include "../lib/ratchet.hpp"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

using namespace Molch;

static void keypair(PrivateKey& private_key, PublicKey& public_key) {
	crypto_box_keypair(public_key, private_key);
	private_key.empty = false;
	public_key.empty = false;
}

int main() {
	try {
		Molch::sodium_init();

		//generate the keys
		//Alice:
		PrivateKey alice_private_identity;
		PublicKey alice_public_identity;
		keypair(alice_private_identity, alice_public_identity);
		PrivateKey alice_private_ephemeral;
		PublicKey alice_public_ephemeral;
		keypair(alice_private_ephemeral, alice_public_ephemeral);
		//Bob:
		PrivateKey bob_private_identity;
		PublicKey bob_public_identity;
		keypair(bob_private_identity, bob_public_identity);
		PrivateKey bob_private_ephemeral;
		PublicKey bob_public_ephemeral;
		keypair(bob_private_ephemeral, bob_public_ephemeral);

		//compare public identity keys, the one with the bigger key will be alice
		//(to make the test more predictable, and make the 'role' flag in the
		// ratchet match the names here)
		if (bob_public_identity > alice_public_identity) {
			//swap bob and alice
			std::swap(alice_public_identity, bob_public_identity);
			std::swap(alice_private_identity, bob_private_identity);
		}

		//initialise the ratchets
		//Alice
		auto alice_send_ratchet{std::make_unique<Ratchet>(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral)};
		auto alice_receive_ratchet{std::make_unique<Ratchet>(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral)};
		//Bob
		auto bob_send_ratchet{std::make_unique<Ratchet>(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral)};
		auto bob_receive_ratchet{std::make_unique<Ratchet>(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral)};

		// FIRST SCENARIO: ALICE SENDS A MESSAGE TO BOB
		HeaderKey send_header_key;
		MessageKey send_message_key;
		PublicKey public_send_ephemeral;
		uint32_t send_message_number;
		uint32_t previous_send_message_number;
		alice_send_ratchet->send(
				send_header_key,
				send_message_number,
				previous_send_message_number,
				public_send_ephemeral,
				send_message_key);

		//bob receives
		HeaderKey current_receive_header_key;
		HeaderKey next_receive_header_key;
		bob_receive_ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		auto decryptability{[&]() {
			if (send_header_key == current_receive_header_key) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (send_header_key == next_receive_header_key) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}()};
		bob_receive_ratchet->setHeaderDecryptability(decryptability);

		MessageKey receive_message_key;
		bob_receive_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key."};
		}
		printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

		bob_receive_ratchet->setLastMessageAuthenticity(true);


		//SECOND SCENARIO: BOB SENDS MESSAGE TO ALICE
		bob_send_ratchet->send(
				send_header_key,
				send_message_number,
				previous_send_message_number,
				public_send_ephemeral,
				send_message_key);

		//alice receives
		alice_receive_ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		decryptability = [&]() {
			if (send_header_key == current_receive_header_key) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (send_header_key == next_receive_header_key) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		alice_receive_ratchet->setHeaderDecryptability(decryptability);

		alice_receive_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key."};
		}
		printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

		alice_receive_ratchet->setLastMessageAuthenticity(true);

		//THIRD SCENARIO: BOB ANSWERS ALICE AFTER HAVING RECEIVED HER FIRST MESSAGE
		bob_receive_ratchet->send(
				send_header_key,
				send_message_number,
				previous_send_message_number,
				public_send_ephemeral,
				send_message_key);

		//alice receives
		alice_send_ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		decryptability = [&]() {
			if (send_header_key == current_receive_header_key) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (send_header_key == next_receive_header_key) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		alice_send_ratchet->setHeaderDecryptability(decryptability);

		alice_send_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key."};
		}
		printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

		alice_send_ratchet->setLastMessageAuthenticity(true);

		//FOURTH SCENARIO: ALICE ANSWERS BOB AFTER HAVING RECEIVED HER FIRST MESSAGE
		alice_receive_ratchet->send(
				send_header_key,
				send_message_number,
				previous_send_message_number,
				public_send_ephemeral,
				send_message_key);

		//bob receives
		bob_send_ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		decryptability = [&]() {
			if (send_header_key == current_receive_header_key) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (send_header_key == next_receive_header_key) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		bob_send_ratchet->setHeaderDecryptability(decryptability);

		bob_send_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key."};
		}
		printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

		bob_send_ratchet->setLastMessageAuthenticity(true);
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
