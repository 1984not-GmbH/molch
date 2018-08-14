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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <exception>
#include <iostream>

#include "../lib/conversation-store.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"

using namespace Molch;

static std::vector<Buffer> protobuf_export(const ConversationStore& store) {
	Arena pool;
	auto exported_conversations{store.exportProtobuf(pool)};

	std::vector<Buffer> export_buffers;
	export_buffers.reserve(exported_conversations.size());

	//unpack all the conversations
	for (const auto& conversation : exported_conversations) {
		auto unpacked_size{molch__protobuf__conversation__get_packed_size(conversation)};
		export_buffers.emplace_back(unpacked_size, 0);
		TRY_VOID(export_buffers.back().setSize(molch__protobuf__conversation__pack(conversation, byte_to_uchar(export_buffers.back().data()))));
	}

	return export_buffers;
}

static ConversationStore protobuf_import(Arena& pool, const std::vector<Buffer> buffers) {
	std::unique_ptr<ProtobufCConversation*[]> conversation_array;
	if (!buffers.empty()) {
		conversation_array = std::unique_ptr<ProtobufCConversation*[]>(new ProtobufCConversation*[buffers.size()]);
	}

	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//unpack all the conversations
	size_t index{0};
	for (const auto& buffer : buffers) {
		conversation_array[index] = molch__protobuf__conversation__unpack(&pool_protoc_allocator, buffer.size(), byte_to_uchar(buffer.data()));
		if (conversation_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf."};
		}
		index++;
	}

	//import
	return ConversationStore({conversation_array.get(), buffers.size()});
}

static void test_add_conversation(ConversationStore& store) {
	PrivateKey our_private_identity;
	PublicKey our_public_identity;
	TRY_VOID(crypto_box_keypair(our_public_identity, our_private_identity));

	PrivateKey our_private_ephemeral;
	PublicKey our_public_ephemeral;
	TRY_VOID(crypto_box_keypair(our_public_ephemeral, our_private_ephemeral));

	PublicKey their_public_identity;
	their_public_identity.fillRandom();

	PublicKey their_public_ephemeral;
	their_public_ephemeral.fillRandom();

	//create the conversation manually
	TRY_WITH_RESULT(conversation, Molch::Conversation::create(
		our_private_identity,
		our_public_identity,
		their_public_identity,
		our_private_ephemeral,
		our_public_ephemeral,
		their_public_ephemeral));

	store.add(std::move(conversation.value()));
}

static void protobuf_empty_store() {
	printf("Testing im-/export of empty conversation store.\n");

	ProtobufCConversation **exported = nullptr;
	size_t exported_length{0};

	ConversationStore store;

	//export it
	Arena pool;
	auto exported_conversations{store.exportProtobuf(pool)};

	if ((exported != nullptr) || (exported_length != 0)) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported data is not empty."};
	}

	//import it
	store = ConversationStore{exported_conversations};
	printf("Successful.\n");
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		// list an empty conversation store
		ConversationStore store;
		auto empty_list{store.list()};
		if (!empty_list.isNone()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "List of empty conversation store is not nullptr."};
		}

		// add five conversations
		printf("Add five conversations.\n");
		for (size_t i{0}; i < 5; i++) {
			printf("%zu\n", i);
			test_add_conversation(store);
			if (store.size() != (i + 1)) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Conversation store has incorrect length."};
			}
		}

		//test list export feature
		auto conversation_list{store.list()};
		if (conversation_list.size() != (CONVERSATION_ID_SIZE * store.size())) {
			throw Molch::Exception{status_type::DATA_FETCH_ERROR, "Failed to get list of conversations."};
		}

		//check for all conversations that they exist
		ConversationId first_id;
		ConversationId middle_id;
		ConversationId last_id;
		for (size_t i{0}; i < (conversation_list.size() / CONVERSATION_ID_SIZE); i++) {
		    TRY_WITH_RESULT(current_id_result, ConversationId::fromSpan({&conversation_list[CONVERSATION_ID_SIZE * i], CONVERSATION_ID_SIZE}));
		    const auto& current_id{current_id_result.value()};
			auto found_node{store.find(current_id)};
			if (found_node == nullptr) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Exported list of conversations was incorrect."};
			}

			if (i == 0) {
				first_id = current_id;
			} else if (i == 2) {
				middle_id = current_id;
			} else if (i == 4) {
				last_id = current_id;
			}
		}

		//test protobuf export
		printf("Export to Protobuf-C\n");
		auto protobuf_export_buffers{protobuf_export(store)};

		printf("protobuf_export_buffers_length = %zu\n", protobuf_export_buffers.size());
		//print
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_buffers.size(); i++) {
			protobuf_export_buffers[i].printHex(std::cout);
			puts(",\n");
		}
		puts("]\n\n");

		store.clear();

		//import again
		Arena pool;
		store = protobuf_import(pool, protobuf_export_buffers);

		//export the imported
		auto protobuf_second_export_buffers{protobuf_export(store)};

		//compare to previous export
		if (protobuf_export_buffers != protobuf_second_export_buffers) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Exported protobuf-c strings don't match."};
		}
		printf("Exported Protobuf-C strings match.\n");

		//remove nodes
		auto first{store.find(first_id)};
		store.remove(first);
		printf("Removed head.\n");
		store.remove(middle_id);
		printf("Removed tail.\n");
		store.remove(last_id);

		if (store.size() != 2) {
			throw Molch::Exception{status_type::REMOVE_ERROR, "Failed to remove nodes."};
		}
		printf("Successfully removed nodes.\n");

		//clear the conversation store
		printf("Clear the conversation store.\n");

		protobuf_empty_store();
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
