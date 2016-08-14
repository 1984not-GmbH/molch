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

#include "conversation-store.h"

/*
 * Init new conversation store.
 */
void conversation_store_init(conversation_store * const store) {
	store->length = 0;
	store->head = NULL;
	store->tail = NULL;
}

/*
 * add a conversation to the conversation store.
 */
return_status conversation_store_add(
		conversation_store * const store,
		conversation_t * const conversation) {

	return_status status = return_status_init();

	if ((store == NULL) || (conversation == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_store_add");
	}

	if (store->head == NULL) { //first conversation in the list
		conversation->previous = NULL;
		conversation->next = NULL;
		store->head = conversation;
		store->tail = conversation;

		//update length
		store->length++;

		goto cleanup;
	}

	//add the new conversation to the tail of the list
	store->tail->next = conversation;
	conversation->previous = store->tail;
	conversation->next = NULL;
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
	if ((store == NULL) || (node == NULL)) {
		return;
	}


	if ((node->next != NULL) && (node != store->tail)) { //node is not the tail
		node->next->previous = node->previous;
	} else {
		store->tail = node->previous;
	}

	if ((node->previous != NULL) && (node != store->head)) { //node is not the head
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
void conversation_store_remove_by_id(conversation_store * const store, const buffer_t * const id) {
	return_status status = return_status_init();

	conversation_t *node = NULL;
	status = conversation_store_find_node(&node, store, id);
	on_error(
		return_status_destroy_errors(&status);
		return;
	)
	if (node == NULL) {
		return;
	}

	conversation_store_remove(store, node);
}

/*
 * Find a conversation for a given conversation ID.
 *
 * Returns NULL if no conversation was found.
 */
return_status conversation_store_find_node(
		conversation_t ** const conversation,
		conversation_store * const store,
		const buffer_t * const id) {
	return_status status = return_status_init();

	if ((conversation == NULL) || (store == NULL) || (id == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_store_find.");
	}

	*conversation = NULL;

	conversation_store_foreach(store,
			if (buffer_compare(value->id, id) == 0) {
				*conversation = node;
				break;
			}
		);

cleanup:

	return status;
}

/*
 * Remove all entries from a conversation store.
 */
void conversation_store_clear(conversation_store * const store) {
	if (store == NULL) {
		return;
	}

	while (store->length > 0) {
		conversation_store_remove(store, store->tail);
	}
}

/*
 * Create a list of conversations (one buffer filled with the conversation ids.
 *
 * Returns NULL if empty.
 */
return_status conversation_store_list(buffer_t ** const list, conversation_store * const store) {
	return_status status = return_status_init();

	if ((list == NULL) || (store == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_store_list.");
	}

	if (store->length == 0) {
		*list = NULL;
		goto cleanup;
	}

	*list = buffer_create_on_heap(store->length * CONVERSATION_ID_SIZE, 0);
	throw_on_failed_alloc(*list);
	//copy all the id's
	conversation_store_foreach(
			store,
			int status_int = buffer_copy(
				*list,
				CONVERSATION_ID_SIZE * index,
				value->id,
				0,
				value->id->content_length);
			if (status_int != 0) {
				throw(BUFFER_ERROR, "Failed to copy conversation id.");
			}
	);

cleanup:
	if (status.status != SUCCESS) {
		if (list != NULL) {
			if (*list != NULL) {
				buffer_destroy_from_heap_and_null(*list);
			}
		}
	}

	return status;
}

/*
 * Serialise a conversation store into JSON. It gets a mempool_t buffer and stre a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of failure.
 */
mcJSON *conversation_store_json_export(const conversation_store * const store, mempool_t * const pool) {
	if ((store == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateArray(pool);
	if (json == NULL) {
		return NULL;
	}

	//add all the conversations to the array
	conversation_store_foreach(store,
		mcJSON * conversation = conversation_json_export(node, pool);
		if (conversation == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(json, conversation, pool);
	);

	return json;
}

/*
 * Deserialise a conversation store (import from JSON).
 */
int conversation_store_json_import(
		const mcJSON * const json,
		conversation_store * const store) {

	return_status status = return_status_init();

	conversation_t *node = NULL;

	if ((json == NULL) || (json->type != mcJSON_Array) || (store == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_store_json_import.");
	}

	//initialise the conversation store
	conversation_store_init(store);

	//iterate through array
	mcJSON *child = json->child;
	for (size_t i = 0; (i < json->length) && (child != NULL); i++, child = child->next) {
		//import the conversation
		node = conversation_json_import(child);
		if (node == NULL) {
			throw(IMPORT_ERROR, "Failed to import conversation from JSON.");
		}

		//add it to the conversation store
		status = conversation_store_add(store, node);
		throw_on_error(ADDITION_ERROR, "Failed to add conversation to conversation store.");

		node = NULL;
	}

cleanup:
	if (status.status != 0) {
		if (node != NULL) {
			conversation_destroy(node);
		}

		if (store != NULL) {
			conversation_store_clear(store);
		}
	}

	return_status_destroy_errors(&status);

	return status.status;
}
