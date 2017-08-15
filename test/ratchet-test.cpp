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
#include <exception>
#include <iostream>

#include "../lib/ratchet.hpp"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "common.hpp"

std::unique_ptr<Buffer> protobuf_export(Ratchet& ratchet) {
	std::unique_ptr<Conversation,ConversationDeleter> conversation = ratchet.exportProtobuf();

	size_t export_size = conversation__get_packed_size(conversation.get());
	auto export_buffer = std::make_unique<Buffer>(export_size, 0);
	export_buffer->content_length = conversation__pack(conversation.get(), export_buffer->content);
	if (export_size != export_buffer->content_length) {
		throw MolchException(EXPORT_ERROR, "Failed to export ratchet.");
	}

	return export_buffer;
}

std::unique_ptr<Ratchet> protobuf_import(const Buffer& export_buffer) {
	//unpack the buffer
	auto conversation = std::unique_ptr<Conversation,ConversationDeleter>(
		conversation__unpack(
			&protobuf_c_allocators,
			export_buffer.content_length,
			export_buffer.content));
	if (!conversation) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
	}

	//now do the import
	return std::make_unique<Ratchet>(*conversation);
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create all the buffers
		//alice keys
		Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer alice_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		//bob keys
		Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer bob_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		//alice send message and header keys
		Buffer alice_send_message_key1(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer alice_send_header_key1(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_send_ephemeral1(PUBLIC_KEY_SIZE, 0);
		Buffer alice_send_message_key2(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
		Buffer alice_send_header_key2(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_send_ephemeral2(PUBLIC_KEY_SIZE, 0);
		Buffer alice_send_message_key3(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer alice_send_header_key3(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_send_ephemeral3(PUBLIC_KEY_SIZE, 0);
		//bobs receive keys
		Buffer bob_current_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_receive_key1(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer bob_receive_key2(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer bob_receive_key3(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		//bobs śend message and header keys
		Buffer bob_send_message_key1(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer bob_send_header_key1(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_send_ephemeral1(PUBLIC_KEY_SIZE, 0);
		Buffer bob_send_message_key2(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer bob_send_header_key2(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_send_ephemeral2(PUBLIC_KEY_SIZE, 0);
		Buffer bob_send_message_key3(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer bob_send_header_key3(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_send_ephemeral3(PUBLIC_KEY_SIZE, 0);
		//alice receive keys
		Buffer alice_current_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_receive_message_key1(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer alice_receive_message_key2(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer alice_receive_message_key3(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		Buffer alice_receive_header_key2(HEADER_KEY_SIZE, HEADER_KEY_SIZE);


		exception_on_invalid_buffer(alice_private_identity);
		exception_on_invalid_buffer(alice_public_identity);
		exception_on_invalid_buffer(alice_private_ephemeral);
		exception_on_invalid_buffer(alice_public_ephemeral);
		//bob keys
		exception_on_invalid_buffer(bob_private_identity);
		exception_on_invalid_buffer(bob_public_identity);
		exception_on_invalid_buffer(bob_private_ephemeral);
		exception_on_invalid_buffer(bob_public_ephemeral);
		//alice send message and header keys
		exception_on_invalid_buffer(alice_send_message_key1);
		exception_on_invalid_buffer(alice_send_header_key1);
		exception_on_invalid_buffer(alice_send_ephemeral1);
		exception_on_invalid_buffer(alice_send_message_key2);
		exception_on_invalid_buffer(alice_send_header_key2);
		exception_on_invalid_buffer(alice_send_ephemeral2);
		exception_on_invalid_buffer(alice_send_message_key3);
		exception_on_invalid_buffer(alice_send_header_key3);
		exception_on_invalid_buffer(alice_send_ephemeral3);
		//bobs receive keys
		exception_on_invalid_buffer(bob_current_receive_header_key);
		exception_on_invalid_buffer(bob_next_receive_header_key);
		exception_on_invalid_buffer(bob_receive_key1);
		exception_on_invalid_buffer(bob_receive_key2);
		exception_on_invalid_buffer(bob_receive_key3);
		//bobs śend message and header keys
		exception_on_invalid_buffer(bob_send_message_key1);
		exception_on_invalid_buffer(bob_send_header_key1);
		exception_on_invalid_buffer(bob_send_ephemeral1);
		exception_on_invalid_buffer(bob_send_message_key2);
		exception_on_invalid_buffer(bob_send_header_key2);
		exception_on_invalid_buffer(bob_send_ephemeral2);
		exception_on_invalid_buffer(bob_send_message_key3);
		exception_on_invalid_buffer(bob_send_header_key3);
		exception_on_invalid_buffer(bob_send_ephemeral3);
		//alice receive keys
		exception_on_invalid_buffer(alice_current_receive_header_key);
		exception_on_invalid_buffer(alice_next_receive_header_key);
		exception_on_invalid_buffer(alice_receive_message_key1);
		exception_on_invalid_buffer(alice_receive_message_key2);
		exception_on_invalid_buffer(alice_receive_message_key3);
		exception_on_invalid_buffer(alice_receive_header_key2);

		//creating Alice's identity keypair
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//creating Alice's ephemeral keypair
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//creating Bob's identity keypair
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//creating Bob's ephemeral keypair
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//start new ratchet for alice
		printf("Creating new ratchet for Alice ...\n");
		auto alice_state = std::make_unique<Ratchet>(
				alice_private_identity,
				alice_public_identity,
				bob_public_identity,
				alice_private_ephemeral,
				alice_public_ephemeral,
				bob_public_ephemeral);
		alice_private_ephemeral.clear();
		alice_private_identity.clear();
		putchar('\n');
		//print Alice's initial root and chain keys
		printf("Alice's initial root key (%zu Bytes):\n", alice_state->storage->root_key.content_length);
		std::cout << alice_state->storage->root_key.toHex();
		printf("Alice's initial chain key (%zu Bytes):\n", alice_state->storage->send_chain_key.content_length);
		std::cout << alice_state->storage->send_chain_key.toHex();
		putchar('\n');

		//start new ratchet for bob
		printf("Creating new ratchet for Bob ...\n");
		auto bob_state = std::make_unique<Ratchet>(
				bob_private_identity,
				bob_public_identity,
				alice_public_identity,
				bob_private_ephemeral,
				bob_public_ephemeral,
				alice_public_ephemeral);
		putchar('\n');
		//print Bob's initial root and chain keys
		printf("Bob's initial root key (%zu Bytes):\n", bob_state->storage->root_key.content_length);
		std::cout << bob_state->storage->root_key.toHex();
		printf("Bob's initial chain key (%zu Bytes):\n", bob_state->storage->send_chain_key.content_length);
		std::cout << bob_state->storage->send_chain_key.toHex();
		putchar('\n');

		//compare Alice's and Bob's initial root and chain keys
		int status = alice_state->storage->root_key.compare(&bob_state->storage->root_key);
		if (status != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's and Bob's initial root keys arent't the same.");
		}
		printf("Alice's and Bob's initial root keys match!\n");

		//initial chain key
		status = alice_state->storage->receive_chain_key.compare(&bob_state->storage->send_chain_key);
		if (status != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's and Bob's initial chain keys aren't the same.");
		}
		printf("Alice's and Bob's initial chain keys match!\n\n");

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//first, alice sends two messages
		uint32_t alice_send_message_number1;
		uint32_t alice_previous_message_number1;
		alice_state->send(
				alice_send_header_key1,
				alice_send_message_number1,
				alice_previous_message_number1,
				alice_send_ephemeral1,
				alice_send_message_key1);
		//print the send message key
		printf("Alice Ratchet 1 send message key 1:\n");
		std::cout << alice_send_message_key1.toHex();
		printf("Alice Ratchet 1 send header key 1:\n");
		std::cout << alice_send_header_key1.toHex();
		putchar('\n');

		//second message key
		uint32_t alice_send_message_number2;
		uint32_t alice_previous_message_number2;
		alice_state->send(
				alice_send_header_key2,
				alice_send_message_number2,
				alice_previous_message_number2,
				alice_send_ephemeral2,
				alice_send_message_key2);
		//print the send message key
		printf("Alice Ratchet 1 send message key 2:\n");
		std::cout << alice_send_message_key2.toHex();
		printf("Alice Ratchet 1 send header key 2:\n");
		std::cout << alice_send_header_key2.toHex();
		putchar('\n');

		//third message_key
		uint32_t alice_send_message_number3;
		uint32_t alice_previous_message_number3;
		alice_state->send(
				alice_send_header_key3,
				alice_send_message_number3,
				alice_previous_message_number3,
				alice_send_ephemeral3,
				alice_send_message_key3);
		//print the send message key
		printf("Alice Ratchet 1 send message key 3:\n");
		std::cout << alice_send_message_key3.toHex();
		printf("Alice Ratchet 1 send header key 3:\n");
		std::cout << alice_send_header_key3.toHex();
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//get pointers to bob's receive header keys
		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's first current receive header key:\n");
		std::cout << bob_current_receive_header_key.toHex();
		printf("Bob's first next receive_header_key:\n");
		std::cout << bob_next_receive_header_key.toHex();
		putchar('\n');

		//check header decryptability
		ratchet_header_decryptability decryptable = NOT_TRIED;
		if (bob_current_receive_header_key == alice_send_header_key1) {
			decryptable = CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (bob_next_receive_header_key == alice_send_header_key1) {
			decryptable = NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//now the receive end, Bob recreates the message keys

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		bob_state->receive(
				bob_receive_key1,
				alice_send_ephemeral1,
				0, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 1:\n");
		std::cout << bob_receive_key1.toHex();
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's second current receive header key:\n");
		std::cout << bob_current_receive_header_key.toHex();
		printf("Bob's second next receive_header_key:\n");
		std::cout << bob_next_receive_header_key.toHex();
		putchar('\n');

		//check header decryptability
		if (bob_current_receive_header_key == alice_send_header_key2) {
			decryptable = CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (bob_next_receive_header_key == alice_send_header_key2) {
			decryptable = NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		//second receive message key
		bob_state->receive(
				bob_receive_key2,
				alice_send_ephemeral2,
				1, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 2:\n");
		std::cout << bob_receive_key2.toHex();
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's third current receive header key:\n");
		std::cout << bob_current_receive_header_key.toHex();
		printf("Bob's third next receive_header_key:\n");
		std::cout << bob_next_receive_header_key.toHex();
		putchar('\n');

		//check header decryptability
		if (bob_current_receive_header_key == alice_send_header_key3) {
			decryptable = CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (bob_next_receive_header_key == alice_send_header_key3) {
			decryptable = NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		//third receive message key
		bob_state->receive(
				bob_receive_key3,
				alice_send_ephemeral3,
				2, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 3:\n");
		std::cout << bob_receive_key3.toHex();
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		//compare the message keys
		if (alice_send_message_key1 != bob_receive_key1) {
			throw MolchException(INCORRECT_DATA, "Alice's first send key and Bob's first receive key aren't the same.");
		}
		printf("Alice's first send key and Bob's first receive key match.\n");

		//second key
		if (alice_send_message_key2 != bob_receive_key2) {
			throw MolchException(INCORRECT_DATA, "Alice's second send key and Bob's second receive key aren't the same.");
		}
		printf("Alice's second send key and Bob's second receive key match.\n");

		//third key
		if (alice_send_message_key3 != bob_receive_key3) {
			throw MolchException(INCORRECT_DATA, "Alice's third send key and Bob's third receive key aren't the same.");
		}
		printf("Alice's third send key and Bob's third receive key match.\n");
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//Now Bob replies with three messages
		uint32_t bob_send_message_number1;
		uint32_t bob_previous_message_number1;
		bob_state->send(
				bob_send_header_key1,
				bob_send_message_number1,
				bob_previous_message_number1,
				bob_send_ephemeral1,
				bob_send_message_key1);
		//print the send message key
		printf("Bob Ratchet 2 send message key 1:\n");
		std::cout << bob_send_message_key1.toHex();
		printf("Bob Ratchet 2 send header key 1:\n");
		std::cout << bob_send_header_key1.toHex();
		putchar('\n');

		//second message key
		uint32_t bob_send_message_number2;
		uint32_t bob_previous_message_number2;
		bob_state->send(
				bob_send_header_key2,
				bob_send_message_number2,
				bob_previous_message_number2,
				bob_send_ephemeral2,
				bob_send_message_key2);
		//print the send message key
		printf("Bob Ratchet 2 send message key 1:\n");
		std::cout << bob_send_message_key2.toHex();
		printf("Bob Ratchet 2 send header key 1:\n");
		std::cout << bob_send_header_key2.toHex();
		putchar('\n');

		//third message key
		uint32_t bob_send_message_number3;
		uint32_t bob_previous_message_number3;
		bob_state->send(
				bob_send_header_key3,
				bob_send_message_number3,
				bob_previous_message_number3,
				bob_send_ephemeral3,
				bob_send_message_key3);
		//print the send message key
		printf("Bob Ratchet 2 send message key 3:\n");
		std::cout << bob_send_message_key3.toHex();
		printf("Bob Ratchet 2 send header key 3:\n");
		std::cout << bob_send_header_key3.toHex();
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//get pointers to alice's receive header keys
		alice_state->getReceiveHeaderKeys(alice_current_receive_header_key, alice_next_receive_header_key);

		printf("Alice's first current receive header key:\n");
		std::cout << alice_current_receive_header_key.toHex();
		printf("Alice's first next receive_header_key:\n");
		std::cout << alice_next_receive_header_key.toHex();
		putchar('\n');

		//check header decryptability
		if (alice_current_receive_header_key == bob_send_header_key1) {
			decryptable = CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (alice_next_receive_header_key == bob_send_header_key1) {
			decryptable = NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}
		bob_send_header_key1.clear();
		alice_current_receive_header_key.clear();
		alice_next_receive_header_key.clear();

		//now alice receives the first, then the third message (second message skipped)

		//set the header decryptability
		alice_state->setHeaderDecryptability(decryptable);

		alice_state->receive(
				alice_receive_message_key1,
				bob_send_ephemeral1,
				0, //purported message number
				0); //purported previous message number
		//print it out
		printf("Alice Ratchet 2 receive message key 1:\n");
		std::cout << alice_receive_message_key1.toHex();
		putchar('\n');

		//confirm validity of the message key
		alice_state->setLastMessageAuthenticity(true);

		alice_state->getReceiveHeaderKeys(alice_current_receive_header_key, alice_next_receive_header_key);

		printf("Alice's current receive header key:\n");
		std::cout << alice_current_receive_header_key.toHex();
		printf("Alice's next receive_header_key:\n");
		std::cout << alice_next_receive_header_key.toHex();
		putchar('\n');

		//check header decryptability
		if (alice_current_receive_header_key == bob_send_header_key3) {
			decryptable = CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (alice_next_receive_header_key == bob_send_header_key3) {
			decryptable = NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}
		bob_send_header_key3.clear();
		alice_current_receive_header_key.clear();
		alice_next_receive_header_key.clear();

		//set the header decryptability
		alice_state->setHeaderDecryptability(decryptable);

		//third received message key (second message skipped)
		alice_state->receive(alice_receive_message_key3, bob_send_ephemeral3, 2, 0);
		//print it out
		printf("Alice Ratchet 2 receive message key 3:\n");
		std::cout << alice_receive_message_key3.toHex();
		putchar('\n');

		assert(alice_state->staged_header_and_message_keys.keys.size() == 1);

		//confirm validity of the message key
		alice_state->setLastMessageAuthenticity(true);

		assert(alice_state->staged_header_and_message_keys.keys.size() == 0);
		assert(alice_state->skipped_header_and_message_keys.keys.size() == 1);

		//get the second receive message key from the message and header keystore
		status = alice_receive_message_key2.cloneFrom(&alice_state->skipped_header_and_message_keys.keys.back().message_key);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to get Alice's second receive message key.");
		}
		printf("Alice Ratchet 2 receive message key 2:\n");
		std::cout << alice_receive_message_key2.toHex();
		putchar('\n');

		//get the second receive header key from the message and header keystore
		status = alice_receive_header_key2.cloneFrom(&alice_state->skipped_header_and_message_keys.keys.back().header_key);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to get Alice's second receive header key.");
		}
		printf("Alice Ratchet 2 receive header key 2:\n");
		std::cout << alice_receive_header_key2.toHex();
		putchar('\n');

		//compare header keys
		if (alice_receive_header_key2 != bob_send_header_key2) {
			throw MolchException(INCORRECT_DATA, "Bob's second send header key and Alice's receive header key aren't the same.");
		}
		printf("Bob's second send header key and Alice's receive header keys match.\n");

		//compare the keys
		if (bob_send_message_key1 != alice_receive_message_key1) {
			throw MolchException(INCORRECT_DATA, "Bob's first send key and Alice's first receive key aren't the same.");
		}
		printf("Bob's first send key and Alice's first receive key match.\n");

		//second key
		if (bob_send_message_key2 != alice_receive_message_key2) {
			throw MolchException(INCORRECT_DATA, "Bob's second send key and Alice's second receive key aren't the same.");
		}
		printf("Bob's second send key and Alice's second receive key match.\n");

		//third key
		if (bob_send_message_key3 != alice_receive_message_key3) {
			throw MolchException(INCORRECT_DATA, "Bob's third send key and Alice's third receive key aren't the same.");
		}
		printf("Bob's third send key and Alice's third receive key match.\n\n");


		//export Alice's ratchet to Protobuf-C
		printf("Export to Protobuf-C!\n");
		std::unique_ptr<Buffer> protobuf_export_buffer = protobuf_export(*alice_state);

		std::cout << protobuf_export_buffer->toHex();
		puts("\n\n");

		alice_state.reset();

		//import again
		printf("Import from Protobuf-C!\n");
		alice_state = protobuf_import(*protobuf_export_buffer);

		//export again
		std::unique_ptr<Buffer> protobuf_second_export_buffer = protobuf_export(*alice_state);

		//compare both exports
		if ((protobuf_export_buffer == NULL) || (protobuf_export_buffer->compare(protobuf_second_export_buffer.get()) != 0)) {
			std::cout << protobuf_second_export_buffer->toHex();
			throw MolchException(INCORRECT_DATA, "Both exports don't match!");
		}
		printf("Exported Protobuf-C buffers match!\n");

		//destroy the ratchets again
		printf("Destroying Alice's ratchet ...\n");
		alice_state.reset();
		printf("Destroying Bob's ratchet ...\n");
		bob_state.reset();
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
