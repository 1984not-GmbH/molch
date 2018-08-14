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
#include "utils.hpp"

using namespace Molch;

static void keypair(PrivateKey& private_key, PublicKey& public_key) {
	TRY_VOID(crypto_box_keypair(public_key, private_key));
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

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
		TRY_WITH_RESULT(alice_send_ratchet_result, Ratchet::create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral));
		auto& alice_send_ratchet{alice_send_ratchet_result.value()};
		TRY_WITH_RESULT(alice_receive_ratchet_result, Ratchet::create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral));
		auto& alice_receive_ratchet{alice_receive_ratchet_result.value()};
		//Bob
		TRY_WITH_RESULT(bob_send_ratchet_result, Ratchet::create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral));
		auto& bob_send_ratchet{bob_send_ratchet_result.value()};
		TRY_WITH_RESULT(bob_receive_ratchet_result, Ratchet::create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral));
		auto& bob_receive_ratchet{bob_receive_ratchet_result.value()};

		// FIRST SCENARIO: ALICE SENDS A MESSAGE TO BOB
		TRY_WITH_RESULT(alice_send_data_result, alice_send_ratchet.getSendData());
		const auto& alice_send_data{alice_send_data_result.value()};

		//bob receives
		const auto bob_receive_header_keys1{bob_receive_ratchet.getReceiveHeaderKeys()};

		auto decryptability{[&]() {
			if (alice_send_data.header_key == bob_receive_header_keys1.current) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (alice_send_data.header_key == bob_receive_header_keys1.next) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}()};
		TRY_VOID(bob_receive_ratchet.setHeaderDecryptability(decryptability));

		TRY_WITH_RESULT(bob_receive_message_key1_result, bob_receive_ratchet.receive(
				alice_send_data.ephemeral,
				alice_send_data.message_number,
				alice_send_data.previous_message_number));
		const auto& bob_receive_message_key1{bob_receive_message_key1_result.value()};

		//now check if the message key is the same
		if (alice_send_data.message_key != bob_receive_message_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key."};
		}
		printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

		bob_receive_ratchet.setLastMessageAuthenticity(true);


		//SECOND SCENARIO: BOB SENDS MESSAGE TO ALICE
		TRY_WITH_RESULT(bob_send_data_result, bob_send_ratchet.getSendData());
		const auto& bob_send_data{bob_send_data_result.value()};

		//alice receives
		const auto alice_receive_header_keys1{alice_receive_ratchet.getReceiveHeaderKeys()};

		decryptability = [&]() {
			if (bob_send_data.header_key == alice_receive_header_keys1.current) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_send_data.header_key == alice_receive_header_keys1.next) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		TRY_VOID(alice_receive_ratchet.setHeaderDecryptability(decryptability));

		TRY_WITH_RESULT(alice_receive_message_key1_result, alice_receive_ratchet.receive(
				bob_send_data.ephemeral,
				bob_send_data.message_number,
				bob_send_data.previous_message_number));
		const auto& alice_receive_message_key1{alice_receive_message_key1_result.value()};

		//now check if the message key is the same
		if (bob_send_data.message_key != alice_receive_message_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key."};
		}
		printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

		alice_receive_ratchet.setLastMessageAuthenticity(true);

		//THIRD SCENARIO: BOB ANSWERS ALICE AFTER HAVING RECEIVED HER FIRST MESSAGE
		TRY_WITH_RESULT(bob_send_data2_result, bob_receive_ratchet.getSendData());
		const auto& bob_send_data2{bob_send_data2_result.value()};

		//alice receives
		const auto alice_receive_header_keys2{alice_send_ratchet.getReceiveHeaderKeys()};

		decryptability = [&]() {
			if (bob_send_data2.header_key == alice_receive_header_keys2.current) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_send_data2.header_key == alice_receive_header_keys2.next) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		TRY_VOID(alice_send_ratchet.setHeaderDecryptability(decryptability));

		TRY_WITH_RESULT(alice_receive_message_key2_result, alice_send_ratchet.receive(
				bob_send_data2.ephemeral,
				bob_send_data2.message_number,
				bob_send_data2.previous_message_number));
		const auto& alice_receive_message_key2{alice_receive_message_key2_result.value()};

		//now check if the message key is the same
		if (bob_send_data2.message_key != alice_receive_message_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key."};
		}
		printf("SUCCESS: Alice' receive message key is the same as Bobs send message key.\n");

		alice_send_ratchet.setLastMessageAuthenticity(true);

		//FOURTH SCENARIO: ALICE ANSWERS BOB AFTER HAVING RECEIVED HER FIRST MESSAGE
		TRY_WITH_RESULT(alice_send_data2_result, alice_receive_ratchet.getSendData());
		const auto& alice_send_data2{alice_send_data2_result.value()};

		//bob receives
		const auto bob_receive_header_keys2{bob_send_ratchet.getReceiveHeaderKeys()};

		decryptability = [&]() {
			if (alice_send_data2.header_key == bob_receive_header_keys2.current) {
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (alice_send_data2.header_key == bob_receive_header_keys2.next) {
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			}

			return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
		}();
		TRY_VOID(bob_send_ratchet.setHeaderDecryptability(decryptability));

		TRY_WITH_RESULT(bob_receive_message_key2_result, bob_send_ratchet.receive(
				alice_send_data2.ephemeral,
				alice_send_data2.message_number,
				alice_send_data2.previous_message_number));
		const auto& bob_receive_message_key2{bob_receive_message_key2_result.value()};

		//now check if the message key is the same
		if (alice_send_data2.message_key != bob_receive_message_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key."};
		}
		printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

		bob_send_ratchet.setLastMessageAuthenticity(true);
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
