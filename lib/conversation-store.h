/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include "conversation.h"
#include "return-status.h"

#ifndef LIB_CONVERSATION_STORE_H
#define LIB_CONVERSATION_STORE_H

typedef struct conversation_store {
	size_t length;
	conversation_t *head;
	conversation_t *tail;
} conversation_store;

/*
 * Init new conversation store.
 */
void conversation_store_init(conversation_store * const store);

/*
 * add a conversation to the conversation store.
 */
return_status conversation_store_add(
		conversation_store * const store,
		conversation_t * const conversation) __attribute__((warn_unused_result));

/*
 * Remove a conversation from the conversation_store.
 */
void conversation_store_remove(conversation_store * const store, conversation_t * const node);

/*
 * Remove a conversation from the conversation store.
 *
 * The conversation is identified by it's id.
 */
void conversation_store_remove_by_id(conversation_store * const store, const buffer_t * const id);

/*
 * Find a conversation for a given conversation ID.
 *
 * Returns NULL if no conversation was found.
 */
return_status conversation_store_find_node(
		conversation_t ** const conversation,
		conversation_store * const store,
		const buffer_t * const id) __attribute__((warn_unused_result));

/*
 * Remove all entries from a conversation store.
 */
void conversation_store_clear(conversation_store * const store);

/*
 * Loop through the conversation_store. In each iteration, the variables
 * 'index', 'node' and 'value' are available.
 */
#define conversation_store_foreach(store, code) {\
	if (store != NULL) {\
		conversation_t *node = store->head;\
		for (size_t index = 0; (index < store->length) && (node != NULL); index++, node = node->next) {\
			conversation_t *value __attribute__((unused));\
			value = node;\
			code\
		}\
	}\
}

/*
 * Create a list of conversations (one buffer filled with the conversation ids.
 *
 * Returns NULL if empty.
 */
return_status conversation_store_list(buffer_t ** const list, conversation_store * const store) __attribute__((warn_unused_result));

/*
 * Serialise a conversation store into JSON. It gets a mempool_t buffer and stre a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of failure.
 */
mcJSON *conversation_store_json_export(const conversation_store * const store, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialise a conversation store (import from JSON).
 */
int conversation_store_json_import(
		const mcJSON * const json,
		conversation_store * const store) __attribute__((warn_unused_result));
#endif
