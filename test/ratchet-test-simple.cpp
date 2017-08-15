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

static int keypair(Buffer& private_key, Buffer& public_key) {
	return crypto_box_keypair(public_key.content, private_key.content);
}

int main(void) {
	try {
		int status = sodium_init();
		if (status != 0) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create all the buffers
		//Keys:
		//Alice:
		Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer alice_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		//Bob
		Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer bob_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

		//keys for sending
		Buffer send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer send_message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer public_send_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

		//keys for receiving
		Buffer current_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer receive_message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);

		exception_on_invalid_buffer(alice_private_identity);
		exception_on_invalid_buffer(alice_public_identity);
		exception_on_invalid_buffer(alice_private_ephemeral);
		exception_on_invalid_buffer(alice_public_ephemeral);
		exception_on_invalid_buffer(send_header_key);
		exception_on_invalid_buffer(send_message_key);
		exception_on_invalid_buffer(public_send_ephemeral);
		exception_on_invalid_buffer(current_receive_header_key);
		exception_on_invalid_buffer(next_receive_header_key);
		exception_on_invalid_buffer(receive_message_key);

		//generate the keys
		if (keypair(alice_private_identity, alice_public_identity) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate Alice' identity keypair.");
		}
		if (keypair(alice_private_ephemeral, alice_public_ephemeral) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate Alice' ephemeral keypair.");
		}
		if (keypair(bob_private_identity, bob_public_identity) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate Bobs identity keypair.");
		}
		if (keypair(bob_private_ephemeral, bob_public_ephemeral) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate Bobs ephemeral keypair.");
		}

		//compare public identity keys, the one with the bigger key will be alice
		//(to make the test more predictable, and make the 'am_i_alice' flag in the
		// ratchet match the names here)
		if (sodium_compare(bob_public_identity.content, alice_public_identity.content, PUBLIC_KEY_SIZE) > 0) {
			status = 0;
			//swap bob and alice
			//public identity key
			Buffer stash(std::max(PUBLIC_KEY_SIZE, PRIVATE_KEY_SIZE), 0);
			exception_on_invalid_buffer(stash);
			status |= stash.cloneFrom(&alice_public_identity);
			status |= alice_public_identity.cloneFrom(&bob_public_identity);
			status |= bob_public_identity.cloneFrom(&stash);

			//private identity key
			status |= stash.cloneFrom(&alice_private_identity);
			status |= alice_private_identity.cloneFrom(&bob_private_identity);
			status |= bob_private_identity.cloneFrom(&stash);

			if (status != 0) {
				throw MolchException(BUFFER_ERROR, "Failed to switch Alice' and Bob's keys.");
			}
		}

		//initialise the ratchets
		//Alice
		auto alice_send_ratchet = std::make_unique<Ratchet>(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
		auto alice_receive_ratchet = std::make_unique<Ratchet>(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
		//Bob
		auto bob_send_ratchet = std::make_unique<Ratchet>(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
		auto bob_receive_ratchet = std::make_unique<Ratchet>(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);

		// FIRST SCENARIO: ALICE SENDS A MESSAGE TO BOB
		uint32_t send_message_number;
		uint32_t previous_send_message_number;
		alice_send_ratchet->send(
				send_header_key,
				send_message_number,
				previous_send_message_number,
				public_send_ephemeral,
				send_message_key);

		//bob receives
		bob_receive_ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		ratchet_header_decryptability decryptability;
		if (send_header_key == current_receive_header_key) {
			decryptability = CURRENT_DECRYPTABLE;
		} else if (send_header_key == next_receive_header_key) {
			decryptability = NEXT_DECRYPTABLE;
		} else {
			decryptability = UNDECRYPTABLE;
		}
		bob_receive_ratchet->setHeaderDecryptability(decryptability);

		bob_receive_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw MolchException(INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key.");
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

		if (send_header_key == current_receive_header_key) {
			decryptability = CURRENT_DECRYPTABLE;
		} else if (send_header_key == next_receive_header_key) {
			decryptability = UNDECRYPTABLE;
		}
		alice_receive_ratchet->setHeaderDecryptability(decryptability);

		alice_receive_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw MolchException(INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key.");
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

		if (send_header_key == current_receive_header_key) {
			decryptability = CURRENT_DECRYPTABLE;
		} else if (send_header_key == next_receive_header_key) {
			decryptability = NEXT_DECRYPTABLE;
		} else {
			decryptability = UNDECRYPTABLE;
		}
		alice_send_ratchet->setHeaderDecryptability(decryptability);

		alice_send_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw MolchException(INCORRECT_DATA, "Alice' receive message key isn't the same as Bobs send message key.");
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

		if (send_header_key == current_receive_header_key) {
			decryptability = CURRENT_DECRYPTABLE;
		} else if (send_header_key == next_receive_header_key) {
			decryptability = NEXT_DECRYPTABLE;
		} else {
			decryptability = UNDECRYPTABLE;
		}
		bob_send_ratchet->setHeaderDecryptability(decryptability);

		bob_send_ratchet->receive(
				receive_message_key,
				public_send_ephemeral,
				send_message_number,
				previous_send_message_number);

		//now check if the message key is the same
		if (send_message_key != receive_message_key) {
			throw MolchException(INCORRECT_DATA, "Bobs receive message key isn't the same as Alice' send message key.");
		}
		printf("SUCCESS: Bobs receive message key is the same as Alice' send message key.\n");

		bob_send_ratchet->setLastMessageAuthenticity(true);
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
