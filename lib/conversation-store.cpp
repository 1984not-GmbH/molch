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

#include "conversation-store.h"

/*
 * Init new conversation store.
 */
void conversation_store_init(conversation_store * const store) {
	store->length = 0;
	store->head = nullptr;
	store->tail = nullptr;
}

/*
 * add a conversation to the conversation store.
 */
return_status conversation_store_add(
		conversation_store * const store,
		conversation_t * const conversation) {

	return_status status = return_status_init();

	if ((store == nullptr) || (conversation == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_add");
	}

	if (store->head == nullptr) { //first conversation in the list
		conversation->previous = nullptr;
		conversation->next = nullptr;
		store->head = conversation;
		store->tail = conversation;

		//update length
		store->length++;

		goto cleanup;
	}

	//add the new conversation to the tail of the list
	store->tail->next = conversation;
	conversation->previous = store->tail;
	conversation->next = nullptr;
	store->tail = conversation;

	//update length
	store->length++;

cleanup:

	return status;
}

/*
 * Remove a conversation from the conversation_store.
 */
void conversation_store_remove(conversation_store * const store, conversation_t * const node) {
	if ((store == nullptr) || (node == nullptr)) {
		return;
	}


	if ((node->next != nullptr) && (node != store->tail)) { //node is not the tail
		node->next->previous = node->previous;
	} else {
		store->tail = node->previous;
	}

	if ((node->previous != nullptr) && (node != store->head)) { //node is not the head
		node->previous->next = node->next;
	} else {
		store->head = node->next;
	}

	store->length--;

	conversation_destroy(node);
}

/*
 * Remove a conversation from the conversation store.
 *
 * The conversation is identified by it's id.
 */
void conversation_store_remove_by_id(conversation_store * const store, Buffer * const id) {
	return_status status = return_status_init();

	conversation_t *node = nullptr;
	status = conversation_store_find_node(&node, store, id);
	on_error {
		return_status_destroy_errors(&status);
		return;
	}
	if (node == nullptr) {
		return;
	}

	conversation_store_remove(store, node);
}

/*
 * Find a conversation for a given conversation ID.
 *
 * Returns nullptr if no conversation was found.
 */
return_status conversation_store_find_node(
		conversation_t ** const conversation,
		conversation_store * const store,
		Buffer * const id) {
	return_status status = return_status_init();

	if ((conversation == nullptr) || (store == nullptr) || (id == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_find.");
	}

	*conversation = nullptr;

	conversation_store_foreach(store,
		if (value->id.compare(id) == 0) {
			*conversation = node;
			break;
		}
	)

cleanup:

	return status;
}

/*
 * Remove all entries from a conversation store.
 */
void conversation_store_clear(conversation_store * const store) {
	if (store == nullptr) {
		return;
	}

	while (store->length > 0) {
		conversation_store_remove(store, store->tail);
	}
}

/*
 * Create a list of conversations (one buffer filled with the conversation ids.
 *
 * Returns nullptr if empty.
 */
return_status conversation_store_list(Buffer ** const list, conversation_store * const store) {
	return_status status = return_status_init();

	if ((list == nullptr) || (store == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_list.");
	}

	if (store->length == 0) {
		*list = nullptr;
		goto cleanup;
	}

	*list = buffer_create_on_heap(store->length * CONVERSATION_ID_SIZE, 0);
	THROW_on_failed_alloc(*list);
	//copy all the id's
	conversation_store_foreach(
			store,
			int status_int = buffer_copy(
				*list,
				CONVERSATION_ID_SIZE * index,
				&value->id,
				0,
				value->id.content_length);
			if (status_int != 0) {
				THROW(BUFFER_ERROR, "Failed to copy conversation id.");
			}
	)

cleanup:
	on_error {
		if (list != nullptr) {
				buffer_destroy_from_heap_and_null_if_valid(*list);
		}
	}

	return status;
}

return_status conversation_store_export(
		const conversation_store * const store,
		Conversation *** const conversations,
		size_t * const length) {
	return_status status = return_status_init();

	//check input
	if ((store == nullptr) || (conversations == nullptr) || (length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input conversation_store_export.");
	}

	if (store->length > 0) {
		//allocate the array of conversations
		*conversations = (Conversation**)zeroed_malloc(store->length * sizeof(Conversation*));
		THROW_on_failed_alloc(*conversations);
		std::fill(*conversations, *conversations + store->length, nullptr);
	} else {
		*conversations = nullptr;
	}

	//export the conversations
	{
		conversation_t *node = store->head;
		for (size_t i = 0; (i < store->length) && (node != nullptr); i++, node = node->next) {
			status = conversation_export(node, &(*conversations)[i]);
			THROW_on_error(EXPORT_ERROR, "Failed to export conversation.");
		}
	}

	*length = store->length;

cleanup:
	on_error {
		if ((store != nullptr) && (conversations != nullptr) && (*conversations != nullptr)) {
			for (size_t i = 0; i < store->length; i++) {
				if ((*conversations)[i] != nullptr) {
					conversation__free_unpacked((*conversations)[i], &protobuf_c_allocators);
					(*conversations)[i] = nullptr;
				}
			}
		}
	}

	return status;
}

return_status conversation_store_import(
		conversation_store * const store,
		Conversation ** const conversations,
		const size_t length) {
	return_status status = return_status_init();

	conversation_t *conversation = nullptr;

	//check input
	if ((store == nullptr)
			|| ((length > 0) && (conversations == nullptr))
			|| ((length == 0) && (conversations != nullptr))) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_import");
	}

	conversation_store_init(store);

	//import all the conversations
	for (size_t i = 0; i < length; i++) {
		status = conversation_import(
			&conversation,
			conversations[i]);
		THROW_on_error(IMPORT_ERROR, "Failed to import conversation.");

		status = conversation_store_add(store, conversation);
		THROW_on_error(ADDITION_ERROR, "Failed to add conversation to conversation store.");
		conversation = nullptr;
	}

cleanup:
	on_error {
		if (conversation != nullptr) {
			conversation_destroy(conversation);
			conversation = nullptr;
		}

		if (store != nullptr) {
			conversation_store_clear(store);
		}
	}

	return status;
}

