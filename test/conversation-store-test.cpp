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

static return_status protobuf_export(
		const ConversationStore * const store,
		Buffer *** const export_buffers,
		size_t * const buffer_count) noexcept __attribute__((warn_unused_result));
static return_status protobuf_export(
		const ConversationStore * const store,
		Buffer *** const export_buffers,
		size_t * const buffer_count) noexcept {
	return_status status = return_status_init();

	Conversation ** conversations = nullptr;
	size_t length = 0;

	if (export_buffers != nullptr) {
		*export_buffers = nullptr;
	}
	if (buffer_count != nullptr) {
		*buffer_count = 0;
	}

	//check input
	if ((store == nullptr) || (export_buffers == nullptr) || (buffer_count == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	status = store->exportConversationStore(conversations, length);
	THROW_on_error(EXPORT_ERROR, "Failed to export conversations.");

	*export_buffers = reinterpret_cast<Buffer**>(malloc(length * sizeof(Buffer*)));
	THROW_on_failed_alloc(*export_buffers);
	*buffer_count = length;

	//unpack all the conversations
	for (size_t i = 0; i < length; i++) {
		size_t unpacked_size = conversation__get_packed_size(conversations[i]);
		(*export_buffers)[i] = Buffer::create(unpacked_size, 0);
		THROW_on_failed_alloc((*export_buffers)[i]);

		(*export_buffers)[i]->content_length = conversation__pack(conversations[i], (*export_buffers)[i]->content);
	}

cleanup:
	if (conversations != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (conversations[i] != nullptr) {
				conversation__free_unpacked(conversations[i], &protobuf_c_allocators);
				conversations[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(conversations);
	}
	//buffer will be freed in main
	return status;
}

return_status protobuf_import(
		ConversationStore * const store,
		Buffer ** const buffers,
		const size_t length) noexcept __attribute__((warn_unused_result));
return_status protobuf_import(
		ConversationStore * const store,
		Buffer ** const buffers,
		const size_t length) noexcept {
	return_status status = return_status_init();

	Conversation **conversations = nullptr;

	//check input
	if ((store == nullptr)
			|| ((length > 0) && (buffers == nullptr))
			|| ((length == 0) && (buffers != nullptr))) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	//allocate the array
	if (length > 0) {
		conversations = reinterpret_cast<Conversation**>(zeroed_malloc(length * sizeof(Conversation*)));
		THROW_on_failed_alloc(conversations);
		std::fill(conversations, conversations + length, nullptr);
	}

	for (size_t i = 0; i < length; i++) {
		conversations[i] = conversation__unpack(&protobuf_c_allocators, buffers[i]->content_length, buffers[i]->content);
		if (conversations[i] == nullptr) {
			THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
		}
	}

	//import
	status = store->import(conversations, length);
	THROW_on_error(IMPORT_ERROR, "Failed to import conversation store.");

cleanup:
	if (conversations != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (conversations[i] != nullptr) {
				conversation__free_unpacked(conversations[i], &protobuf_c_allocators);
				conversations[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(conversations);
	}

	return status;
}

static return_status test_add_conversation(ConversationStore * const store) noexcept {
	//define key buffers
	//identity keys
	Buffer our_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer our_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer their_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//ephemeral keys
	Buffer our_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer our_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer their_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	conversation_t *conversation = nullptr;

	return_status status = return_status_init();

	//generate the keys
	int status_int = 0;
	throw_on_invalid_buffer(our_private_identity);
	throw_on_invalid_buffer(our_public_identity);
	throw_on_invalid_buffer(their_public_identity);
	throw_on_invalid_buffer(our_private_ephemeral);
	throw_on_invalid_buffer(our_public_ephemeral);
	throw_on_invalid_buffer(their_public_ephemeral);

	status_int = crypto_box_keypair(our_public_identity.content, our_private_identity.content);
	if (status_int != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate our identity keys.");
	}
	status_int = crypto_box_keypair(our_public_ephemeral.content, our_private_ephemeral.content);
	if (status_int != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate our ephemeral keys.");
	}
	status_int = their_public_identity.fillRandom(their_public_identity.getBufferLength());
	if (status_int != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate their public identity keys.");
	}
	status_int = their_public_ephemeral.fillRandom(their_public_ephemeral.getBufferLength());
	if (status_int != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate their public ephemeral keys.");
	}

	//create the conversation manually
	conversation = reinterpret_cast<conversation_t*>(malloc(sizeof(conversation_t)));
	if (conversation == nullptr) {
		THROW(ALLOCATION_FAILED, "Failed to allocate conversation.");
	}

	conversation->next = nullptr;
	conversation->previous = nullptr;
	conversation->ratchet = nullptr;

	//create the conversation id
	conversation->id.init(conversation->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);

	status_int = conversation->id.fillRandom(CONVERSATION_ID_SIZE);
	if (status_int != 0) {
		THROW(GENERIC_ERROR, "Failed to fill buffer with random data.");
	}

	try {
		conversation->ratchet = new Ratchet(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);

		status = store->add(conversation);
		conversation = nullptr;
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

cleanup:
	if (conversation != nullptr) {
		conversation_destroy(conversation);
	}

	return status;
}

return_status protobuf_empty_store(void) noexcept __attribute__((warn_unused_result));
return_status protobuf_empty_store(void) noexcept {
	return_status status = return_status_init();

	printf("Testing im-/export of empty conversation store.\n");

	Conversation **exported = nullptr;
	size_t exported_length = 0;

	ConversationStore store;
	store.init();

	//export it
	status = store.exportConversationStore(exported, exported_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export empty conversation store.");

	if ((exported != nullptr) || (exported_length != 0)) {
		THROW(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	status = store.import(exported, exported_length);
	THROW_on_error(IMPORT_ERROR, "Failed to import empty conversation store.");

	printf("Successful.\n");

cleanup:
	return status;
}

int main(void) noexcept {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//protobuf buffers
	Buffer ** protobuf_export_buffers = nullptr;
	size_t protobuf_export_buffers_length = 0;
	Buffer ** protobuf_second_export_buffers = nullptr;
	size_t protobuf_second_export_buffers_length = 0;

	ConversationStore *store = reinterpret_cast<ConversationStore*>(malloc(sizeof(ConversationStore)));
	if (store == nullptr) {
		THROW(ALLOCATION_FAILED, "Failed to allocate conversation store.");
	}

	printf("Initialize the conversation store.\n");
	store->init();

	// list an empty conversation store
	Buffer *empty_list;
	status = store->list(empty_list);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list empty conversation store.");
	if (empty_list != nullptr) {
		THROW(INCORRECT_DATA, "List of empty conversation store is not nullptr.");
	}

	// add five conversations
	printf("Add five conversations.\n");
	for (size_t i = 0; i < 5; i++) {
		printf("%zu\n", i);
		status = test_add_conversation(store);
		THROW_on_error(ADDITION_ERROR, "Failed to add test conversation.");
		if (store->getLength() != (i + 1)) {
			THROW(INCORRECT_DATA, "Conversation store has incorrect length.");
		}
	}

	//find node by id
	{
		conversation_t *found_node = store->findNode(store->head->next->next->id);
		if (found_node != store->head->next->next) {
			THROW(NOT_FOUND, "Failed to find node by ID.");
		}
		printf("Found node by ID.\n");

		//test list export feature
		Buffer *conversation_list = nullptr;
		status = store->list(conversation_list);
		on_error {
			THROW(DATA_FETCH_ERROR, "Failed to list conversations.");
		}
		if ((conversation_list == nullptr) || (conversation_list->content_length != (CONVERSATION_ID_SIZE * store->getLength()))) {
			THROW(DATA_FETCH_ERROR, "Failed to get list of conversations.");
		}

		//check for all conversations that they exist
		for (size_t i = 0; i < (conversation_list->content_length / CONVERSATION_ID_SIZE); i++) {
			Buffer current_id(conversation_list->content + CONVERSATION_ID_SIZE * i, CONVERSATION_ID_SIZE);
			found_node = store->findNode(current_id);
			if (found_node == nullptr) {
				buffer_destroy_and_null_if_valid(conversation_list);
				THROW(INCORRECT_DATA, "Exported list of conversations was incorrect.");
			}
		}
		buffer_destroy_and_null_if_valid(conversation_list);
	}

	//test protobuf export
	printf("Export to Protobuf-C\n");
	status = protobuf_export(store, &protobuf_export_buffers, &protobuf_export_buffers_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export conversation store.");

	printf("protobuf_export_buffers_length = %zu\n", protobuf_export_buffers_length);
	//print
	puts("[\n");
	for (size_t i = 0; i < protobuf_export_buffers_length; i++) {
		std::cout << protobuf_export_buffers[i]->toHex();
		puts(",\n");
	}
	puts("]\n\n");

	store->clear();

	//import again
	status = protobuf_import(store, protobuf_export_buffers, protobuf_export_buffers_length);
	THROW_on_error(IMPORT_ERROR, "Failed to import conversation store from Protobuf-C.");

	//export the imported
	status = protobuf_export(store, &protobuf_second_export_buffers, &protobuf_second_export_buffers_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export imported conversation store again to Protobuf-C.");

	//compare to previous export
	if (protobuf_export_buffers_length != protobuf_second_export_buffers_length) {
		THROW(INCORRECT_DATA, "Both arrays of Protobuf-C strings don't have the same length.");
	}
	for (size_t i = 0; i < protobuf_export_buffers_length; i++) {
		if (protobuf_export_buffers[i]->compare(protobuf_second_export_buffers[i]) != 0) {
			THROW(INCORRECT_DATA, "Exported protobuf-c string doesn't match.");
		}
	}
	printf("Exported Protobuf-C strings match.\n");

	//remove nodes
	store->remove(store->head);
	printf("Removed head.\n");
	store->remove(store->tail);
	printf("Removed tail.\n");
	store->remove(store->head->next);

	if (store->getLength() != 2) {
		THROW(REMOVE_ERROR, "Failed to remove nodes.");
	}
	printf("Successfully removed nodes.\n");

	//remove node by id
	store->removeById(store->tail->id);
	if (store->getLength() != 1) {
		THROW(REMOVE_ERROR, "Failed to remove node by id.");
	}
	printf("Successfully removed node by id.\n");

	//clear the conversation store
	printf("Clear the conversation store.\n");

	status = protobuf_empty_store();
	THROW_on_error(GENERIC_ERROR, "Failed to im-/export empty conversation store.");

cleanup:
	if (protobuf_export_buffers != nullptr) {
		for (size_t i =0; i < protobuf_export_buffers_length; i++) {
			buffer_destroy_and_null_if_valid(protobuf_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_export_buffers);
	}
	if (protobuf_second_export_buffers != nullptr) {
		for (size_t i =0; i < protobuf_second_export_buffers_length; i++) {
			buffer_destroy_and_null_if_valid(protobuf_second_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_second_export_buffers);
	}

	if (store != nullptr) {
		store->clear();
	}
	free_and_null_if_valid(store);

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
