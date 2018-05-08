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
#include <iterator>

#include "conversation-store.hpp"
#include "destroyers.hpp"
#include "gsl.hpp"

namespace Molch {
	size_t ConversationStore::size() const {
		return this->conversations.size();
	}

	void ConversationStore::add(Conversation&& conversation) {
		const auto& id{conversation.id()};
		//search if a conversation with this id already exists
		auto existing_conversation{std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
				[&id](const Conversation& conversation) {
					return conversation.id() == id;
				})};
		//if none exists, just add the conversation
		if (existing_conversation == std::cend(this->conversations)) {
			this->conversations.push_back(std::move(conversation));
			return;
		}

		//otherwise replace the exiting one
		auto existing_index{gsl::narrow_cast<size_t>(existing_conversation - std::cbegin(this->conversations))};
		this->conversations[existing_index] = std::move(conversation);
	}

	void ConversationStore::remove(const Conversation * const node) {
		if (node == nullptr) {
			return;
		}

		auto found_node{std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
				[&node](const Conversation& conversation) {
					return &conversation == node;
				})};
		if (found_node != std::cend(this->conversations)) {
			this->conversations.erase(found_node);
		}
	}

	/*
	 * Remove a conversation from the conversation store.
	 *
	 * The conversation is identified by it's id.
	 */
	void ConversationStore::remove(const Key<CONVERSATION_ID_SIZE,KeyType::Key>& id) {
		auto found_node{std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
				[&id](const Conversation& conversation) {
					return conversation.id() == id;
				})};

		if (found_node != std::cend(this->conversations)) {
			this->conversations.erase(found_node);
		}
	}

	/*
	 * Find a conversation for a given conversation ID.
	 *
	 * Returns nullptr if no conversation was found.
	 */
	Conversation* ConversationStore::find(const Key<CONVERSATION_ID_SIZE,KeyType::Key>& id) {
		auto node{std::find_if(std::begin(this->conversations), std::end(this->conversations),
				[&id](const Conversation& conversation) {
					return conversation.id() == id;
				})};

		if (node == std::end(this->conversations)) {
			return nullptr;
		}

		return &(*node);
	}

	/*
	 * Remove all entries from a conversation store.
	 */
	void ConversationStore::clear() {
		this->conversations.clear();
	}

	/*
	 * Create a list of conversations (one buffer filled with the conversation ids.
	 *
	 * Returns nullptr if empty.
	 */
	Buffer ConversationStore::list() const {
		if (this->conversations.empty()) {
			return Buffer();
		}

		Buffer list{this->conversations.size() * CONVERSATION_ID_SIZE, 0};

		size_t index{0};
		for (const auto& conversation : this->conversations) {
			list.copyFromRaw(
				CONVERSATION_ID_SIZE * index,
				conversation.id().data(),
				0,
				conversation.id().size());
			index++;
		}

		return list;
	}

	span<ProtobufCConversation*> ConversationStore::exportProtobuf(ProtobufPool& pool) const {
		if (this->conversations.empty()) {
			return {nullptr, static_cast<size_t>(0)};
		}

		//export the conversations
		auto conversations{pool.allocate<ProtobufCConversation*>(this->conversations.size())};
		size_t index{0};
		for (const auto& conversation : this->conversations) {
			conversations[index] = conversation.exportProtobuf(pool);
			index++;
		}

		return {conversations, this->conversations.size()};
	}

	ConversationStore::ConversationStore(const span<ProtobufCConversation*> conversations) {
		//import all the conversations
		for (const auto& conversation : conversations) {
			if (conversation == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Array of conversation has an empty element."};
			}

			this->conversations.emplace_back(*conversation);
		}
	}

	std::ostream& ConversationStore::print(std::ostream& stream) const {
		stream << "Conversations: [\n";
		for (const auto& conversation : this->conversations) {
			conversation.print(stream) << ",\n";
		}
		stream << "]\n";

		return stream;
	}
}
