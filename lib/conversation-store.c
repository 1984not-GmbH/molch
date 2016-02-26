/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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

int add_conversation_store_node(conversation_store * const store, conversation_store_node *node) {
	if ((store == NULL) || (node == NULL)) {
		return -1;
	}

	if (store->head == NULL) { //first node in the list
		node->previous = NULL;
		node->next = NULL;
		store->head = node;
		store->tail = node;

		//update length
		store->length++;

		return 0;
	}

	//add the new node to the tail of the list
	store->tail->next = node;
	node->previous = store->tail;
	node->next = NULL;
	store->tail = node;

	//update length
	store->length++;

	return 0;
}

/*
 * add a conversation to the conversation store.
 */
int conversation_store_add(
		conversation_store * const store,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {
	conversation_store_node *node = malloc(sizeof(conversation_store_node));
	if (node == NULL) {
		return -1;
	}

	//initialize the conversation
	int status = conversation_init(
			node->conversation,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if (status != 0) {
		free(node);
		return status;
	}

	//add to the conversation store
	status = add_conversation_store_node(store, node);
	if (status != 0) {
		conversation_deinit(node->conversation);
		free(node);
		return status;
	}

	return 0;
}

/*
 * Remove a conversation from the conversation_store.
 */
void conversation_store_remove(conversation_store * const store, conversation_store_node * const node) {
	if ((store == NULL) || (node == NULL)) {
		return;
	}

	conversation_deinit(node->conversation);

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

	free(node);
}

/*
 * Remove a conversation from the conversation store.
 *
 * The conversation is identified by it's id.
 */
void conversation_store_remove_by_id(conversation_store * const store, const buffer_t * const id) {
	conversation_store_node *node = conversation_store_find_node(store, id);
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
conversation_store_node *conversation_store_find_node(
		conversation_store * const store,
		const buffer_t * const id) {
	conversation_store_foreach(store,
			if (buffer_compare(value->id, id) == 0) {
				return node;
			}
		);

	return NULL;
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
buffer_t *conversation_store_list(conversation_store * const store) {
	if (store->length == 0) {
		return NULL;
	}

	buffer_t *list = buffer_create_on_heap(store->length * CONVERSATION_ID_SIZE, 0);
	//copy all the id's
	conversation_store_foreach(
			store,
			int status = buffer_copy(
				list,
				CONVERSATION_ID_SIZE * index,
				value->id,
				0,
				value->id->content_length);
			if (status != 0) {
				buffer_destroy_from_heap(list);
				return NULL;
			}
	);

	return list;
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
		mcJSON * conversation = conversation_json_export(node->conversation, pool);
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
	if ((json == NULL) || (json->type != mcJSON_Array) || (store == NULL)) {
		return -1;
	}

	//initialise the conversation store
	conversation_store_init(store);

	//iterate through array
	mcJSON *child = json->child;
	for (size_t i = 0; (i < json->length) && (child != NULL); i++, child = child->next) {
		//create the node
		conversation_store_node *node = malloc(sizeof(conversation_store_node));
		if (node == NULL) {
			free(node);
			conversation_store_clear(store);
			return -2;
		}

		//import the conversation
		int status = conversation_json_import(child, node->conversation);
		if (status != 0) {
			free(node);
			conversation_store_clear(store);
			return status;
		}

		//add it to the conversation store
		status = add_conversation_store_node(store, node);
		if (status != 0) {
			free(node);
			conversation_store_clear(store);
			return status;
		}
	}

	return 0;
}
