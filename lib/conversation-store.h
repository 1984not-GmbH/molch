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
