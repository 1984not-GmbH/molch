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

#include "list.h"
#include "conversation.h"

#ifndef LIB_CONVERSATION_STORE_H
#define LIB_CONVERSATION_STORE_H

typedef struct conversation_store_node conversation_store_node;
struct conversation_store_node {
	//this is identical to list_node
	conversation_store_node *previous;
	conversation_store_node *next;
	conversation_t *data;
	//this is specific for conversation_store_node
	conversation_t conversation[1];
};

//this is identical to list_t
typedef struct conversation_store {
	size_t length;
	conversation_store_node *head;
	conversation_store_node *tail;
} conversation_store;

/*
 * Init new conversation store.
 */
void conversation_store_init(conversation_store * const store);

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
		const buffer_t * const their_public_ephemeral) __attribute__((warn_unused_result));

/*
 * Remove a conversation from the conversation_store.
 */
void conversation_store_remove(conversation_store * const store, conversation_store_node * const node);

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
conversation_store_node *conversation_store_find_node(
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
		conversation_store_node *node = store->head;\
		for (size_t index = 0; (index < store->length) && (node != NULL); index++, node = node->next) {\
			conversation_t *value __attribute__((unused));\
			value = node->data;\
			code\
		}\
	}\
}
#endif
