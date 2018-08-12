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
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

static Buffer protobuf_export(Ratchet& ratchet) {
	Arena pool;
	TRY_WITH_RESULT(conversation_result, ratchet.exportProtobuf(pool));
	const auto& conversation{conversation_result.value()};

	auto export_size{molch__protobuf__conversation__get_packed_size(conversation)};
	Buffer export_buffer{export_size, 0};
	TRY_VOID(export_buffer.setSize(molch__protobuf__conversation__pack(conversation, byte_to_uchar(export_buffer.data()))));
	if (export_size != export_buffer.size()) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export ratchet."};
	}

	return export_buffer;
}

static Ratchet protobuf_import(Arena& pool, const Buffer& export_buffer) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//unpack the buffer
	auto conversation{molch__protobuf__conversation__unpack(
			&pool_protoc_allocator,
			export_buffer.size(),
			byte_to_uchar(export_buffer.data()))};
	if (conversation == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf."};
	}

	//now do the import
	TRY_WITH_RESULT(ratchet_result, Ratchet::import(*conversation));
	return std::move(ratchet_result.value());
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//creating Alice's identity keypair
		EmptyablePublicKey alice_public_identity;
		PrivateKey alice_private_identity;
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//creating Alice's ephemeral keypair
		EmptyablePublicKey alice_public_ephemeral;
		PrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//creating Bob's identity keypair
		EmptyablePublicKey bob_public_identity;
		PrivateKey bob_private_identity;
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//creating Bob's ephemeral keypair
		EmptyablePublicKey bob_public_ephemeral;
		PrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//start new ratchet for alice
		printf("Creating new ratchet for Alice ...\n");
		TRY_WITH_RESULT(alice_state_result, Ratchet::create(
				alice_private_identity,
				alice_public_identity,
				bob_public_identity,
				alice_private_ephemeral,
				alice_public_ephemeral,
				bob_public_ephemeral));
		auto& alice_state{alice_state_result.value()};
		putchar('\n');
		//print Alice's initial root and chain keys
		printf("Alice's initial root key (%zu Bytes):\n", alice_state.storage->root_key.size());
		alice_state.storage->root_key.printHex(std::cout);
		printf("Alice's initial chain key (%zu Bytes):\n", alice_state.storage->send_chain_key.size());
		alice_state.storage->send_chain_key.printHex(std::cout);
		putchar('\n');

		//start new ratchet for bob
		printf("Creating new ratchet for Bob ...\n");
		TRY_WITH_RESULT(bob_state_result, Ratchet::create(
				bob_private_identity,
				bob_public_identity,
				alice_public_identity,
				bob_private_ephemeral,
				bob_public_ephemeral,
				alice_public_ephemeral));
		auto& bob_state{bob_state_result.value()};
		putchar('\n');
		//print Bob's initial root and chain keys
		printf("Bob's initial root key (%zu Bytes):\n", bob_state.storage->root_key.size());
		bob_state.storage->root_key.printHex(std::cout);
		printf("Bob's initial chain key (%zu Bytes):\n", bob_state.storage->send_chain_key.size());
		bob_state.storage->send_chain_key.printHex(std::cout);
		putchar('\n');

		//compare Alice's and Bob's initial root and chain keys
		if (alice_state.storage->root_key != bob_state.storage->root_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial root keys arent't the same."};
		}
		printf("Alice's and Bob's initial root keys match!\n");

		//initial chain key
		if (alice_state.storage->receive_chain_key != bob_state.storage->send_chain_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial chain keys aren't the same."};
		}
		printf("Alice's and Bob's initial chain keys match!\n\n");

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//first, alice sends two messages
		TRY_WITH_RESULT(alice_send_data1_result, alice_state.getSendData());
		const auto& alice_send_data1{alice_send_data1_result.value()};
		//print the send message key
		printf("Alice Ratchet 1 send message key 1:\n");
		std::cout << alice_send_data1.message_key;
		printf("Alice Ratchet 1 send header key 1:\n");
		alice_send_data1.header_key.printHex(std::cout);
		putchar('\n');

		//second message key
		TRY_WITH_RESULT(alice_send_data2_result, alice_state.getSendData());
		const auto& alice_send_data2{alice_send_data2_result.value()};
		//print the send message key
		printf("Alice Ratchet 1 send message key 2:\n");
		std::cout << alice_send_data2.message_key;
		printf("Alice Ratchet 1 send header key 2:\n");
		alice_send_data2.header_key.printHex(std::cout);
		putchar('\n');

		//third message_key
		TRY_WITH_RESULT(alice_send_data3_result, alice_state.getSendData());
		const auto& alice_send_data3{alice_send_data3_result.value()};
		//print the send message key
		printf("Alice Ratchet 1 send message key 3:\n");
		std::cout << alice_send_data3.message_key;
		printf("Alice Ratchet 1 send header key 3:\n");
		alice_send_data3.header_key.printHex(std::cout);
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		const auto bob_receive_header_keys{bob_state.getReceiveHeaderKeys()};

		printf("Bob's first current receive header key:\n");
		bob_receive_header_keys.current.printHex(std::cout);
		printf("Bob's first next receive_header_key:\n");
		bob_receive_header_keys.next.printHex(std::cout) << std::endl;

		//check header decryptability
		auto decryptable{[&]() {
			if (bob_receive_header_keys.current == alice_send_data1.header_key) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_receive_header_keys.next == alice_send_data1.header_key) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}()};

		//now the receive end, Bob recreates the message keys

		//set the header decryptability
		TRY_VOID(bob_state.setHeaderDecryptability(decryptable));

		TRY_WITH_RESULT(bob_receive_key1_result, bob_state.receive(
				alice_send_data1.ephemeral,
				0, //purported message number
				0)); //purported previous message number
		const auto& bob_receive_key1{bob_receive_key1_result.value()};

		//print it out!
		printf("Bob Ratchet 1 receive message key 1:\n");
		std::cout << bob_receive_key1;
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state.setLastMessageAuthenticity(true);

		const auto bob_receive_header_keys2{bob_state.getReceiveHeaderKeys()};

		printf("Bob's second current receive header key:\n");
		bob_receive_header_keys2.current.printHex(std::cout);
		printf("Bob's second next receive_header_key:\n");
		bob_receive_header_keys2.next.printHex(std::cout);
		putchar('\n');

		//check header decryptability
		if (bob_receive_header_keys2.current == alice_send_data2.header_key) {
			decryptable = Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (bob_receive_header_keys2.next == alice_send_data1.header_key) {
			decryptable = Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//set the header decryptability
		TRY_VOID(bob_state.setHeaderDecryptability(decryptable));

		//second receive message key
		TRY_WITH_RESULT(bob_receive_key2_result, bob_state.receive(
				alice_send_data2.ephemeral,
				1, //purported message number
				0)); //purported previous message number
		const auto& bob_receive_key2{bob_receive_key2_result.value()};

		//print it out!
		printf("Bob Ratchet 1 receive message key 2:\n");
		std::cout << bob_receive_key2;
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state.setLastMessageAuthenticity(true);

		const auto bob_receive_header_keys3{bob_state.getReceiveHeaderKeys()};

		printf("Bob's third current receive header key:\n");
		bob_receive_header_keys3.current.printHex(std::cout);
		printf("Bob's third next receive_header_key:\n");
		bob_receive_header_keys3.next.printHex(std::cout);
		putchar('\n');

		//check header decryptability
		decryptable = [&]() {
			if (bob_receive_header_keys3.current == alice_send_data3.header_key) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (bob_receive_header_keys3.next == alice_send_data3.header_key) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}();

		//set the header decryptability
		TRY_VOID(bob_state.setHeaderDecryptability(decryptable));

		//third receive message key
		TRY_WITH_RESULT(bob_receive_key3_result, bob_state.receive(
				alice_send_data3.ephemeral,
				2, //purported message number
				0)); //purported previous message number
		const auto& bob_receive_key3{bob_receive_key3_result.value()};

		//print it out!
		printf("Bob Ratchet 1 receive message key 3:\n");
		std::cout << bob_receive_key3;
		putchar('\n');

		//confirm validity of the message key (this is normally done after successfully decrypting
		//and authenticating a message with the key
		bob_state.setLastMessageAuthenticity(true);

		//compare the message keys
		if (alice_send_data1.message_key != bob_receive_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's first send key and Bob's first receive key aren't the same."};
		}
		printf("Alice's first send key and Bob's first receive key match.\n");

		//second key
		if (alice_send_data2.message_key != bob_receive_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's second send key and Bob's second receive key aren't the same."};
		}
		printf("Alice's second send key and Bob's second receive key match.\n");

		//third key
		if (alice_send_data3.message_key != bob_receive_key3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's third send key and Bob's third receive key aren't the same."};
		}
		printf("Alice's third send key and Bob's third receive key match.\n");
		putchar('\n');

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//Now Bob replies with three messages
		TRY_WITH_RESULT(bob_send_data1_result, bob_state.getSendData());
		const auto& bob_send_data1{bob_send_data1_result.value()};
		//print the send message key
		printf("Bob Ratchet 2 send message key 1:\n");
		std::cout << bob_send_data1.message_key;
		printf("Bob Ratchet 2 send header key 1:\n");
		bob_send_data1.header_key.printHex(std::cout) << std::endl;

		//second message key
		TRY_WITH_RESULT(bob_send_data2_result, bob_state.getSendData());
		const auto& bob_send_data2{bob_send_data2_result.value()};
		//print the send message key
		printf("Bob Ratchet 2 send message key 1:\n");
		std::cout << bob_send_data2.message_key;
		printf("Bob Ratchet 2 send header key 1:\n");
		bob_send_data2.header_key.printHex(std::cout) << std::endl;

		//third message key
		TRY_WITH_RESULT(bob_send_data3_result, bob_state.getSendData());
		const auto& bob_send_data3{bob_send_data3_result.value()};
		//print the send message key
		printf("Bob Ratchet 2 send message key 3:\n");
		std::cout << bob_send_data3.message_key;
		printf("Bob Ratchet 2 send header key 3:\n");
		bob_send_data3.header_key.printHex(std::cout) << std::endl;

		//--------------------------------------------------------------------------
		puts("----------------------------------------\n");
		//get pointers to alice's receive header keys
		const auto alice_receive_header_keys1{alice_state.getReceiveHeaderKeys()};

		printf("Alice's first current receive header key:\n");
		alice_receive_header_keys1.current.printHex(std::cout);
		printf("Alice's first next receive_header_key:\n");
		alice_receive_header_keys1.next.printHex(std::cout) << std::endl;

		//check header decryptability
		if (alice_receive_header_keys1.current == bob_send_data1.header_key) {
			decryptable = Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			printf("Header decryptable with current header key.\n");
		} else if (alice_receive_header_keys1.next == bob_send_data1.header_key) {
			decryptable = Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			printf("Header decryptable with next header key.\n");
		} else {
			decryptable = Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			fprintf(stderr, "Failed to decrypt header.");
		}

		//now alice receives the first, then the third message (second message skipped)

		//set the header decryptability
		TRY_VOID(alice_state.setHeaderDecryptability(decryptable));

		TRY_WITH_RESULT(alice_receive_message_key1_result, alice_state.receive(
				bob_send_data1.ephemeral,
				0, //purported message number
				0)); //purported previous message number
		const auto& alice_receive_message_key1{alice_receive_message_key1_result.value()};

		//print it out
		printf("Alice Ratchet 2 receive message key 1:\n");
		std::cout << alice_receive_message_key1 << std::endl;

		//confirm validity of the message key
		alice_state.setLastMessageAuthenticity(true);

		const auto alice_receive_header_keys2{alice_state.getReceiveHeaderKeys()};

		printf("Alice's current receive header key:\n");
		alice_receive_header_keys2.current.printHex(std::cout);
		printf("Alice's next receive_header_key:\n");
		alice_receive_header_keys2.next.printHex(std::cout) << std::endl;

		//check header decryptability
		decryptable = [&]() {
			if (alice_receive_header_keys2.current == bob_send_data3.header_key) {
				printf("Header decryptable with current header key.\n");
				return Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE;
			} else if (alice_receive_header_keys2.next == bob_send_data3.header_key) {
				printf("Header decryptable with next header key.\n");
				return Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE;
			} else {
				fprintf(stderr, "Failed to decrypt header.");
				return Ratchet::HeaderDecryptability::UNDECRYPTABLE;
			}
		}();

		//set the header decryptability
		TRY_VOID(alice_state.setHeaderDecryptability(decryptable));

		//third received message key (second message skipped)
		TRY_WITH_RESULT(alice_receive_message_key3_result, alice_state.receive(
			bob_send_data3.ephemeral,
			2, //purported_message_number
			0)); //purported_previous_message_number
		const auto& alice_receive_message_key3{alice_receive_message_key3_result.value()};

		//print it out
		printf("Alice Ratchet 2 receive message key 3:\n");
		std::cout << alice_receive_message_key3 << std::endl;

		assert(alice_state.staged_header_and_message_keys.keys().size() == 1);

		//confirm validity of the message key
		alice_state.setLastMessageAuthenticity(true);

		assert(alice_state.staged_header_and_message_keys.keys().empty());
		assert(alice_state.skipped_header_and_message_keys.keys().size() == 1);

		//get the second receive message key from the message and header keystore
		MessageKey alice_receive_message_key2;
		alice_receive_message_key2 = alice_state.skipped_header_and_message_keys.keys().back().messageKey();
		printf("Alice Ratchet 2 receive message key 2:\n");
		std::cout << alice_receive_message_key2 << std::endl;

		//get the second receive header key from the message and header keystore
		EmptyableHeaderKey alice_receive_header_key2;
		alice_receive_header_key2 = alice_state.skipped_header_and_message_keys.keys().back().headerKey();
		printf("Alice Ratchet 2 receive header key 2:\n");
		alice_receive_header_key2.printHex(std::cout) << std::endl;

		//compare header keys
		if (alice_receive_header_key2 != bob_send_data2.header_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's second send header key and Alice's receive header key aren't the same."};
		}
		printf("Bob's second send header key and Alice's receive header keys match.\n");

		//compare the keys
		if (bob_send_data1.message_key != alice_receive_message_key1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's first send key and Alice's first receive key aren't the same."};
		}
		printf("Bob's first send key and Alice's first receive key match.\n");

		//second key
		if (bob_send_data2.message_key != alice_receive_message_key2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's second send key and Alice's second receive key aren't the same."};
		}
		printf("Bob's second send key and Alice's second receive key match.\n");

		//third key
		if (bob_send_data3.message_key != alice_receive_message_key3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's third send key and Alice's third receive key aren't the same."};
		}
		printf("Bob's third send key and Alice's third receive key match.\n\n");


		//export Alice's ratchet to Protobuf-C
		printf("Export to Protobuf-C!\n");
		auto protobuf_export_buffer = protobuf_export(alice_state);

		protobuf_export_buffer.printHex(std::cout) << "\n\n" << std::flush;

		//import again
		printf("Import from Protobuf-C!\n");
		Arena pool;
		alice_state = protobuf_import(pool, protobuf_export_buffer);

		//export again
		auto protobuf_second_export_buffer{protobuf_export(alice_state)};

		//compare both exports
		if (protobuf_export_buffer != protobuf_second_export_buffer) {
			protobuf_second_export_buffer.printHex(std::cout);
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both exports don't match!"};
		}
		printf("Exported Protobuf-C buffers match!\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
