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

#ifndef LIB_CONVERSATION_STORE_H
#define LIB_CONVERSATION_STORE_H

class ConversationStore {
private:
	size_t length;

public:
	conversation_t *head;
	conversation_t *tail;
	size_t getLength() noexcept;

	/*
	 * Init new conversation store.
	 */
	void init() noexcept;

	/*
	 * add a conversation to the conversation store.
	 */
	return_status add(conversation_t * const conversation) noexcept __attribute__((warn_unused_result));

	/*
	 * Remove a conversation from the conversation_store.
	 */
	void remove(conversation_t * const node) noexcept;

	/*
	 * Remove a conversation from the conversation store.
	 *
	 * The conversation is identified by it's id.
	 */
	void removeById(const Buffer& id) noexcept;

	/*
	 * Find a conversation for a given conversation ID.
	 *
	 * Returns nullptr if no conversation was found.
	 */
	conversation_t* findNode(const Buffer& id) noexcept __attribute__((warn_unused_result));

	/*
	 * Remove all entries from a conversation store.
	 */
	void clear() noexcept;

	/*
	 * Create a list of conversations (one buffer filled with the conversation ids.
	 *
	 * Returns nullptr if empty.
	 */
	return_status list(Buffer*& list) noexcept __attribute__((warn_unused_result));

	/*! Export a conversation store to Protobuf-C
	 * \param conversation_store The conversation store to export.
	 * \param conversations An array of Protobuf-C structs to export it to.
	 * \return The status.
	 */
	return_status exportConversationStore(Conversation**& conversations, size_t& length) const noexcept __attribute__((warn_unused_result));

	/*! Import a conversation store from a Protobuf-C struct.
	 * \param conversation_store The conversation store to import to.
	 * \param conversations An array of Protobuf-C structs to import from.
	 * \param length The number of array elements.
	 * \param public_identity_key The public identity key of the user.
	 * \return The status.
	 */
	return_status import(Conversation ** const conversations, const size_t length) noexcept __attribute__((warn_unused_result));
};
#endif
