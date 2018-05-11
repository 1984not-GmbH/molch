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
#include "protobuf-arena.hpp"

namespace Molch {
	class ConversationStore {
	private:
		std::vector<Conversation> conversations;

	public:

		size_t size() const;

		ConversationStore() = default;

		/*! Import a conversation store from a Protobuf-C struct.  */
		ConversationStore(const span<ProtobufCConversation*> conversations);

		ConversationStore(const ConversationStore& store) = delete;
		ConversationStore(ConversationStore&& store) noexcept = default;

		ConversationStore& operator=(const ConversationStore& store) = delete;
		ConversationStore& operator=(ConversationStore&& store) = default;

		/*
		 * Add a conversation to the conversation store or replaces
		 * it if one with the same ID already exists.
		 */
		void add(Conversation&& conversation);

		/*
		 * Remove a conversation from the conversation_store.
		 */
		void remove(const Conversation* const node);

		/*
		 * Remove a conversation from the conversation store.
		 *
		 * The conversation is identified by it's id.
		 */
		void remove(const Key<CONVERSATION_ID_SIZE,KeyType::Key>& id);

		/*
		 * Find a conversation for a given conversation ID.
		 *
		 * Returns nullptr if no conversation was found.
		 */
		Conversation* find(const Key<CONVERSATION_ID_SIZE,KeyType::Key>& id);

		/*
		 * Remove all entries from a conversation store.
		 */
		void clear();

		/*
		 * Create a list of conversations (one buffer filled with the conversation ids.
		 *
		 * Returns nullptr if empty.
		 */
		Buffer list() const;

		/*! Export a conversation store to Protobuf-C */
		span<ProtobufCConversation*> exportProtobuf(Arena& pool) const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif
