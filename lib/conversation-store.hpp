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

#ifndef LIB_CONVERSATION_STORE_H
#define LIB_CONVERSATION_STORE_H

#include <ostream>
#include "conversation.hpp"

class ConversationStore {
private:
	std::vector<ConversationT> conversations;

public:

	size_t size() const;

	ConversationStore() = default;

	/*! Import a conversation store from a Protobuf-C struct.
	 * \param conversations An array of Protobuf-C structs to import from.
	 * \param length The number of array elements.
	 * \param public_identity_key The public identity key of the user.
	 */
	ConversationStore(Conversation** const& conversations, const size_t length);

	ConversationStore(const ConversationStore& store) = delete;
	ConversationStore(ConversationStore&& store) = default;

	ConversationStore& operator=(const ConversationStore& store) = delete;
	ConversationStore& operator=(ConversationStore&& store) = default;

	/*
	 * Add a conversation to the conversation store or replaces
	 * it if one with the same ID already exists.
	 */
	void add(ConversationT&& conversation);

	/*
	 * Remove a conversation from the conversation_store.
	 */
	void remove(const ConversationT* const node);

	/*
	 * Remove a conversation from the conversation store.
	 *
	 * The conversation is identified by it's id.
	 */
	void remove(const Buffer& id);

	/*
	 * Find a conversation for a given conversation ID.
	 *
	 * Returns nullptr if no conversation was found.
	 */
	ConversationT* find(const Buffer& id);

	/*
	 * Remove all entries from a conversation store.
	 */
	void clear();

	/*
	 * Create a list of conversations (one buffer filled with the conversation ids.
	 *
	 * Returns nullptr if empty.
	 */
	std::unique_ptr<Buffer> list() const;

	/*! Export a conversation store to Protobuf-C
	 * \param conversation_store The conversation store to export.
	 * \param conversations An array of Protobuf-C structs to export it to.
	 * \return The status.
	 */
	void exportProtobuf(Conversation**& conversations, size_t& length) const;

	std::ostream& print(std::ostream& stream) const;
};
#endif
