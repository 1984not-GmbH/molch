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

static void free_conversation_array(Conversation**& conversations, size_t length) {
	if (conversations != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (conversations[i] != nullptr) {
				conversation__free_unpacked(conversations[i], &protobuf_c_allocators);
				conversations[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(conversations);
	}
}

static std::vector<Buffer> protobuf_export(const ConversationStore& store) {
	Conversation ** conversations = nullptr;
	size_t length = 0;

	std::vector<Buffer> export_buffers;

	try {
		store.exportProtobuf(conversations, length);

		export_buffers.reserve(length);

		//unpack all the conversations
		for (size_t i = 0; i < length; i++) {
			size_t unpacked_size = conversation__get_packed_size(conversations[i]);
			export_buffers.emplace_back(unpacked_size, 0);
			exception_on_invalid_buffer(export_buffers.back());

			export_buffers.back().content_length = conversation__pack(conversations[i], export_buffers.back().content);
		}
	} catch (const std::exception& exception) {
		free_conversation_array(conversations, length);
		throw exception;
	}

	free_conversation_array(conversations, length);
	return export_buffers;
}

ConversationStore protobuf_import(const std::vector<Buffer> buffers) {
	auto conversations = std::vector<std::unique_ptr<Conversation,ConversationDeleter>>();
	conversations.reserve(buffers.size());

	//unpack all the conversations
	for (const auto& buffer : buffers) {
		conversations.emplace_back(
					conversation__unpack(&protobuf_c_allocators, buffer.content_length, buffer.content));
		if (!conversations.back()) {
			throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
		}
	}

	//allocate the conversation array output array
	std::unique_ptr<Conversation*[]> conversation_array;
	if (!buffers.empty()) {
		conversation_array = std::unique_ptr<Conversation*[]>(new Conversation*[buffers.size()]);
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
	Buffer our_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer our_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(our_private_identity);
	exception_on_invalid_buffer(our_public_identity);
	int status = crypto_box_keypair(our_public_identity.content, our_private_identity.content);
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate our identity keys.");
	}

	Buffer our_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer our_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(our_private_ephemeral);
	exception_on_invalid_buffer(our_public_ephemeral);
	status = crypto_box_keypair(our_public_ephemeral.content, our_private_ephemeral.content);
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate our ephemeral keys.");
	}

	Buffer their_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(their_public_identity);
	status = their_public_identity.fillRandom(their_public_identity.getBufferLength());
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate their public identity keys.");
	}

	Buffer their_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(their_public_ephemeral);
	status = their_public_ephemeral.fillRandom(their_public_ephemeral.getBufferLength());
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate their public ephemeral keys.");
	}

	//create the conversation manually
	ConversationT conversation(
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

	Conversation **exported = nullptr;
	size_t exported_length = 0;

	ConversationStore store;

	//export it
	store.exportProtobuf(exported, exported_length);

	if ((exported != nullptr) || (exported_length != 0)) {
		throw MolchException(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	store = ConversationStore(exported, exported_length);
	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to iniitialize libsodium.");
		}

		// list an empty conversation store
		ConversationStore store;
		auto empty_list = store.list();
		if (empty_list) {
			throw MolchException(INCORRECT_DATA, "List of empty conversation store is not nullptr.");
		}

		// add five conversations
		printf("Add five conversations.\n");
		for (size_t i = 0; i < 5; i++) {
			printf("%zu\n", i);
			test_add_conversation(store);
			if (store.size() != (i + 1)) {
				throw MolchException(INCORRECT_DATA, "Conversation store has incorrect length.");
			}
		}

		//test list export feature
		auto conversation_list = store.list();
		if (!conversation_list || (conversation_list->content_length != (CONVERSATION_ID_SIZE * store.size()))) {
			throw MolchException(DATA_FETCH_ERROR, "Failed to get list of conversations.");
		}

		//check for all conversations that they exist
		Buffer first_id;
		Buffer middle_id;
		Buffer last_id;
		for (size_t i = 0; i < (conversation_list->content_length / CONVERSATION_ID_SIZE); i++) {
			Buffer current_id(conversation_list->content + CONVERSATION_ID_SIZE * i, CONVERSATION_ID_SIZE);
			auto found_node = store.find(current_id);
			if (found_node == nullptr) {
				throw MolchException(INCORRECT_DATA, "Exported list of conversations was incorrect.");
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
			std::cout << protobuf_export_buffers[i].toHex();
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
			throw MolchException(INCORRECT_DATA, "Exported protobuf-c strings don't match.");
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
			throw MolchException(REMOVE_ERROR, "Failed to remove nodes.");
		}
		printf("Successfully removed nodes.\n");

		//clear the conversation store
		printf("Clear the conversation store.\n");

		protobuf_empty_store();
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
