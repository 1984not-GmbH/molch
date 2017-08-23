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
#include "../lib/molch-exception.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"

using namespace Molch;

static std::vector<Buffer> protobuf_export(const ConversationStore& store) {
	ProtobufPool pool;
	ProtobufCConversation ** conversations = nullptr;
	size_t length = 0;
	store.exportProtobuf(pool, conversations, length);

	std::vector<Buffer> export_buffers;
	export_buffers.reserve(length);

	//unpack all the conversations
	for (size_t i = 0; i < length; i++) {
		size_t unpacked_size = conversation__get_packed_size(conversations[i]);
		export_buffers.emplace_back(unpacked_size, 0);
		export_buffers.back().size = conversation__pack(conversations[i], export_buffers.back().content);
	}

	return export_buffers;
}
ConversationStore protobuf_import(const std::vector<Buffer> buffers) {
	auto conversations = std::vector<std::unique_ptr<ProtobufCConversation,ConversationDeleter>>();
	conversations.reserve(buffers.size());

	//unpack all the conversations
	for (const auto& buffer : buffers) {
		conversations.emplace_back(
					conversation__unpack(&protobuf_c_allocators, buffer.size, buffer.content));
		if (!conversations.back()) {
			throw Molch::Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
		}
	}

	//allocate the conversation array output array
	std::unique_ptr<ProtobufCConversation*[]> conversation_array;
	if (!buffers.empty()) {
		conversation_array = std::unique_ptr<ProtobufCConversation*[]>(new ProtobufCConversation*[buffers.size()]);
	}

	size_t index = 0;
	for (const auto& conversation : conversations) {
		conversation_array[index] = conversation.get();
		index++;
	}

	//import
	return ConversationStore(conversation_array.get(), buffers.size());
}

static void test_add_conversation(ConversationStore& store) {
	PrivateKey our_private_identity;
	PublicKey our_public_identity;
	int status = crypto_box_keypair(our_public_identity.data(), our_private_identity.data());
	if (status != 0) {
		throw Molch::Exception(KEYGENERATION_FAILED, "Failed to generate our identity keys.");
	}
	our_private_identity.empty = false;
	our_public_identity.empty = false;

	PrivateKey our_private_ephemeral;
	PublicKey our_public_ephemeral;
	status = crypto_box_keypair(our_public_ephemeral.data(), our_private_ephemeral.data());
	if (status != 0) {
		throw Molch::Exception(KEYGENERATION_FAILED, "Failed to generate our ephemeral keys.");
	}
	our_private_ephemeral.empty = false;
	our_public_ephemeral.empty = false;

	PublicKey their_public_identity;
	their_public_identity.fillRandom();

	PublicKey their_public_ephemeral;
	their_public_ephemeral.fillRandom();

	//create the conversation manually
	Molch::Conversation conversation(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);

	store.add(std::move(conversation));
}

void protobuf_empty_store(void) {
	printf("Testing im-/export of empty conversation store.\n");

	ProtobufCConversation **exported = nullptr;
	size_t exported_length = 0;

	ConversationStore store;

	//export it
	ProtobufPool pool;
	store.exportProtobuf(pool, exported, exported_length);

	if ((exported != nullptr) || (exported_length != 0)) {
		throw Molch::Exception(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	store = ConversationStore(exported, exported_length);
	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception(INIT_ERROR, "Failed to iniitialize libsodium.");
		}

		// list an empty conversation store
		ConversationStore store;
		auto empty_list = store.list();
		if (!empty_list.isNone()) {
			throw Molch::Exception(INCORRECT_DATA, "List of empty conversation store is not nullptr.");
		}

		// add five conversations
		printf("Add five conversations.\n");
		for (size_t i = 0; i < 5; i++) {
			printf("%zu\n", i);
			test_add_conversation(store);
			if (store.size() != (i + 1)) {
				throw Molch::Exception(INCORRECT_DATA, "Conversation store has incorrect length.");
			}
		}

		//test list export feature
		auto conversation_list = store.list();
		if (!conversation_list.contains(CONVERSATION_ID_SIZE * store.size())) {
			throw Molch::Exception(DATA_FETCH_ERROR, "Failed to get list of conversations.");
		}

		//check for all conversations that they exist
		Molch::Key<CONVERSATION_ID_SIZE,Molch::KeyType::Key> first_id;
		Molch::Key<CONVERSATION_ID_SIZE,Molch::KeyType::Key> middle_id;
		Molch::Key<CONVERSATION_ID_SIZE,Molch::KeyType::Key> last_id;
		for (size_t i = 0; i < (conversation_list.size / CONVERSATION_ID_SIZE); i++) {
			Molch::Key<CONVERSATION_ID_SIZE,Molch::KeyType::Key> current_id;
			current_id.set(conversation_list.content + CONVERSATION_ID_SIZE * i, CONVERSATION_ID_SIZE);
			auto found_node = store.find(current_id);
			if (found_node == nullptr) {
				throw Molch::Exception(INCORRECT_DATA, "Exported list of conversations was incorrect.");
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
		auto protobuf_export_buffers = protobuf_export(store);

		printf("protobuf_export_buffers_length = %zu\n", protobuf_export_buffers.size());
		//print
		puts("[\n");
		for (size_t i = 0; i < protobuf_export_buffers.size(); i++) {
			protobuf_export_buffers[i].printHex(std::cout);
			puts(",\n");
		}
		puts("]\n\n");

		store.clear();

		//import again
		store = protobuf_import(protobuf_export_buffers);

		//export the imported
		auto protobuf_second_export_buffers = protobuf_export(store);

		//compare to previous export
		if (protobuf_export_buffers != protobuf_second_export_buffers) {
			throw Molch::Exception(INCORRECT_DATA, "Exported protobuf-c strings don't match.");
		}
		printf("Exported Protobuf-C strings match.\n");

		//remove nodes
		auto first = store.find(first_id);
		store.remove(first);
		printf("Removed head.\n");
		store.remove(middle_id);
		printf("Removed tail.\n");
		store.remove(last_id);

		if (store.size() != 2) {
			throw Molch::Exception(REMOVE_ERROR, "Failed to remove nodes.");
		}
		printf("Successfully removed nodes.\n");

		//clear the conversation store
		printf("Clear the conversation store.\n");

		protobuf_empty_store();
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
