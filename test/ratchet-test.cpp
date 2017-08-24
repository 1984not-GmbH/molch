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

using namespace Molch;

Buffer protobuf_export(Ratchet& ratchet) {
	ProtobufPool pool;
	auto conversation{ratchet.exportProtobuf(pool)};

	auto export_size{conversation__get_packed_size(conversation)};
	Buffer export_buffer{export_size, 0};
	export_buffer.size = conversation__pack(conversation, export_buffer.content);
	if (export_size != export_buffer.size) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export ratchet."};
	}

	return export_buffer;
}

std::unique_ptr<Ratchet> protobuf_import(ProtobufPool& pool, const Buffer& export_buffer) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//unpack the buffer
	auto conversation{conversation__unpack(
			&pool_protoc_allocator,
			export_buffer.size,
			export_buffer.content)};
	if (conversation == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf."};
	}

	//now do the import
	return std::make_unique<Ratchet>(*conversation);
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}

		//creating Alice's identity keypair
		PublicKey alice_public_identity;
		PrivateKey alice_private_identity;
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//creating Alice's ephemeral keypair
		PublicKey alice_public_ephemeral;
		PrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//creating Bob's identity keypair
		PublicKey bob_public_identity;
		PrivateKey bob_private_identity;
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//creating Bob's ephemeral keypair
		PublicKey bob_public_ephemeral;
		PrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//start new ratchet for alice
		printf("Creating new ratchet for Alice ...\n");
		auto alice_state{std::make_unique<Ratchet>(
				alice_private_identity,
				alice_public_identity,
				bob_public_identity,
				alice_private_ephemeral,
				alice_public_ephemeral,
				bob_public_ephemeral)};
		alice_private_ephemeral.clear();
		alice_private_identity.clear();
		putchar('\n');
		//print Alice's initial root and chain keys
		printf("Alice's initial root key (%zu Bytes):\n", alice_state->storage->root_key.size());
		alice_state->storage->root_key.printHex(std::cout);
		printf("Alice's initial chain key (%zu Bytes):\n", alice_state->storage->send_chain_key.size());
		alice_state->storage->send_chain_key.printHex(std::cout);
		putchar('\n');

		//start new ratchet for bob
		printf("Creating new ratchet for Bob ...\n");
		auto bob_state{std::make_unique<Ratchet>(
				bob_private_identity,
				bob_public_identity,
				alice_public_identity,
				bob_private_ephemeral,
				bob_public_ephemeral,
				alice_public_ephemeral)};
		putchar('\n');
		//print Bob's initial root and chain keys
		printf("Bob's initial root key (%zu Bytes):\n", bob_state->storage->root_key.size());
		bob_state->storage->root_key.printHex(std::cout);
		printf("Bob's initial chain key (%zu Bytes):\n", bob_state->storage->send_chain_key.size());
		bob_state->storage->send_chain_key.printHex(std::cout);
		putchar('\n');

		//compare Alice's and Bob's initial root and chain keys
		if (alice_state->storage->root_key != bob_state->storage->root_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial root keys arent't the same."};
		}
		printf("Alice's and Bob's initial root keys match!\n");

		//initial chain key
		if (alice_state->storage->receive_chain_key != bob_state->storage->send_chain_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial chain keys aren't the same."};
		}
		printf("Alice's and Bob's initial chain keys match!\n\n");

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//first, alice sends two messages
		MessageKey alice_send_message_key1;
		HeaderKey alice_send_header_key1;
		PublicKey alice_send_ephemeral1;
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
		alice_send_message_key1.printHex(std::cout);
		printf("Alice Ratchet 1 send header key 1:\n");
		alice_send_header_key1.printHex(std::cout);
		putchar('\n');

		//second message key
		MessageKey alice_send_message_key2;
		HeaderKey alice_send_header_key2;
		PublicKey alice_send_ephemeral2;
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
		alice_send_message_key2.printHex(std::cout);
		printf("Alice Ratchet 1 send header key 2:\n");
		alice_send_header_key2.printHex(std::cout);
		putchar('\n');

		//third message_key
		MessageKey alice_send_message_key3;
		HeaderKey alice_send_header_key3;
		PublicKey alice_send_ephemeral3;
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
		alice_send_message_key3.printHex(std::cout);
		printf("Alice Ratchet 1 send header key 3:\n");
		alice_send_header_key3.printHex(std::cout);
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//get pointers to bob's receive header keys
		HeaderKey bob_current_receive_header_key;
		HeaderKey bob_next_receive_header_key;
		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's first current receive header key:\n");
		bob_current_receive_header_key.printHex(std::cout);
		printf("Bob's first next receive_header_key:\n");
		bob_next_receive_header_key.printHex(std::cout) << std::endl;

		//check header decryptability
		auto decryptable{[&]() {
			if (bob_current_receive_header_key == alice_send_header_key1) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_next_receive_header_key == alice_send_header_key1) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}()};

		//now the receive end, Bob recreates the message keys

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		MessageKey bob_receive_key1;
		bob_state->receive(
				bob_receive_key1,
				alice_send_ephemeral1,
				0, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 1:\n");
		bob_receive_key1.printHex(std::cout);
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's second current receive header key:\n");
		bob_current_receive_header_key.printHex(std::cout);
		printf("Bob's second next receive_header_key:\n");
		bob_next_receive_header_key.printHex(std::cout);
		putchar('\n');

		//check header decryptability
		if (bob_current_receive_header_key == alice_send_header_key2) {
			decryptable = Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (bob_next_receive_header_key == alice_send_header_key2) {
			decryptable = Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		//second receive message key
		MessageKey bob_receive_key2;
		bob_state->receive(
				bob_receive_key2,
				alice_send_ephemeral2,
				1, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 2:\n");
		bob_receive_key2.printHex(std::cout);
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		bob_state->getReceiveHeaderKeys(bob_current_receive_header_key, bob_next_receive_header_key);

		printf("Bob's third current receive header key:\n");
		bob_current_receive_header_key.printHex(std::cout);
		printf("Bob's third next receive_header_key:\n");
		bob_next_receive_header_key.printHex(std::cout);
		putchar('\n');

		//check header decryptability
		decryptable = [&]() {
			if (bob_current_receive_header_key == alice_send_header_key3) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_next_receive_header_key == alice_send_header_key3) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}();

		//set the header decryptability
		bob_state->setHeaderDecryptability(decryptable);

		//third receive message key
		MessageKey bob_receive_key3;
		bob_state->receive(
				bob_receive_key3,
				alice_send_ephemeral3,
				2, //purported message number
				0); //purported previous message number
		//print it out!
		printf("Bob Ratchet 1 receive message key 3:\n");
		bob_receive_key3.printHex(std::cout);
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state->setLastMessageAuthenticity(true);

		//compare the message keys
		if (alice_send_message_key1 != bob_receive_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's first send key and Bob's first receive key aren't the same."};
		}
		printf("Alice's first send key and Bob's first receive key match.\n");

		//second key
		if (alice_send_message_key2 != bob_receive_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's second send key and Bob's second receive key aren't the same."};
		}
		printf("Alice's second send key and Bob's second receive key match.\n");

		//third key
		if (alice_send_message_key3 != bob_receive_key3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's third send key and Bob's third receive key aren't the same."};
		}
		printf("Alice's third send key and Bob's third receive key match.\n");
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//Now Bob replies with three messages
		MessageKey bob_send_message_key1;
		HeaderKey bob_send_header_key1;
		PublicKey bob_send_ephemeral1;
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
		bob_send_message_key1.printHex(std::cout);
		printf("Bob Ratchet 2 send header key 1:\n");
		bob_send_header_key1.printHex(std::cout) << std::endl;

		//second message key
		MessageKey bob_send_message_key2;
		HeaderKey bob_send_header_key2;
		PublicKey bob_send_ephemeral2;
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
		bob_send_message_key2.printHex(std::cout);
		printf("Bob Ratchet 2 send header key 1:\n");
		bob_send_header_key2.printHex(std::cout) << std::endl;

		//third message key
		MessageKey bob_send_message_key3;
		HeaderKey bob_send_header_key3;
		PublicKey bob_send_ephemeral3;
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
		bob_send_message_key3.printHex(std::cout);
		printf("Bob Ratchet 2 send header key 3:\n");
		bob_send_header_key3.printHex(std::cout) << std::endl;

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//get pointers to alice's receive header keys
		HeaderKey alice_current_receive_header_key;
		HeaderKey alice_next_receive_header_key;
		alice_state->getReceiveHeaderKeys(alice_current_receive_header_key, alice_next_receive_header_key);

		printf("Alice's first current receive header key:\n");
		alice_current_receive_header_key.printHex(std::cout);
		printf("Alice's first next receive_header_key:\n");
		alice_next_receive_header_key.printHex(std::cout) << std::endl;

		//check header decryptability
		if (alice_current_receive_header_key == bob_send_header_key1) {
			decryptable = Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (alice_next_receive_header_key == bob_send_header_key1) {
			decryptable = Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}
		bob_send_header_key1.clear();
		alice_current_receive_header_key.clear();
		alice_next_receive_header_key.clear();

		//now alice receives the first, then the third message (second message skipped)

		//set the header decryptability
		alice_state->setHeaderDecryptability(decryptable);

		MessageKey alice_receive_message_key1;
		alice_state->receive(
				alice_receive_message_key1,
				bob_send_ephemeral1,
				0, //purported message number
				0); //purported previous message number
		//print it out
		printf("Alice Ratchet 2 receive message key 1:\n");
		alice_receive_message_key1.printHex(std::cout) << std::endl;

		//confirm validity of the message key
		alice_state->setLastMessageAuthenticity(true);

		alice_state->getReceiveHeaderKeys(alice_current_receive_header_key, alice_next_receive_header_key);

		printf("Alice's current receive header key:\n");
		alice_current_receive_header_key.printHex(std::cout);
		printf("Alice's next receive_header_key:\n");
		alice_next_receive_header_key.printHex(std::cout) << std::endl;

		//check header decryptability
		decryptable = [&]() {
			if (alice_current_receive_header_key == bob_send_header_key3) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (alice_next_receive_header_key == bob_send_header_key3) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}();
		bob_send_header_key3.clear();
		alice_current_receive_header_key.clear();
		alice_next_receive_header_key.clear();

		//set the header decryptability
		alice_state->setHeaderDecryptability(decryptable);

		//third received message key (second message skipped)
		MessageKey alice_receive_message_key3;
		alice_state->receive(alice_receive_message_key3, bob_send_ephemeral3, 2, 0);
		//print it out
		printf("Alice Ratchet 2 receive message key 3:\n");
		alice_receive_message_key3.printHex(std::cout) << std::endl;

		assert(alice_state->staged_header_and_message_keys.keys.size() == 1);

		//confirm validity of the message key
		alice_state->setLastMessageAuthenticity(true);

		assert(alice_state->staged_header_and_message_keys.keys.size() == 0);
		assert(alice_state->skipped_header_and_message_keys.keys.size() == 1);

		//get the second receive message key from the message and header keystore
		MessageKey alice_receive_message_key2;
		alice_receive_message_key2 = alice_state->skipped_header_and_message_keys.keys.back().message_key;
		printf("Alice Ratchet 2 receive message key 2:\n");
		alice_receive_message_key2.printHex(std::cout) << std::endl;

		//get the second receive header key from the message and header keystore
		HeaderKey alice_receive_header_key2;
		alice_receive_header_key2 = alice_state->skipped_header_and_message_keys.keys.back().header_key;
		printf("Alice Ratchet 2 receive header key 2:\n");
		alice_receive_header_key2.printHex(std::cout) << std::endl;

		//compare header keys
		if (alice_receive_header_key2 != bob_send_header_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's second send header key and Alice's receive header key aren't the same."};
		}
		printf("Bob's second send header key and Alice's receive header keys match.\n");

		//compare the keys
		if (bob_send_message_key1 != alice_receive_message_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's first send key and Alice's first receive key aren't the same."};
		}
		printf("Bob's first send key and Alice's first receive key match.\n");

		//second key
		if (bob_send_message_key2 != alice_receive_message_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's second send key and Alice's second receive key aren't the same."};
		}
		printf("Bob's second send key and Alice's second receive key match.\n");

		//third key
		if (bob_send_message_key3 != alice_receive_message_key3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's third send key and Alice's third receive key aren't the same."};
		}
		printf("Bob's third send key and Alice's third receive key match.\n\n");


		//export Alice's ratchet to Protobuf-C
		printf("Export to Protobuf-C!\n");
		auto protobuf_export_buffer = protobuf_export(*alice_state);

		protobuf_export_buffer.printHex(std::cout) << "\n\n" << std::flush;

		alice_state.reset();

		//import again
		printf("Import from Protobuf-C!\n");
		ProtobufPool pool;
		alice_state = protobuf_import(pool, protobuf_export_buffer);

		//export again
		auto protobuf_second_export_buffer{protobuf_export(*alice_state)};

		//compare both exports
		if (protobuf_export_buffer != protobuf_second_export_buffer) {
			protobuf_second_export_buffer.printHex(std::cout);
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both exports don't match!"};
		}
		printf("Exported Protobuf-C buffers match!\n");

		//destroy the ratchets again
		printf("Destroying Alice's ratchet ...\n");
		alice_state.reset();
		printf("Destroying Bob's ratchet ...\n");
		bob_state.reset();
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
