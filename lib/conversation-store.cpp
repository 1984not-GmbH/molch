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

size_t ConversationStore::size() const {
	return this->conversations.size();
}

void ConversationStore::add(ConversationT&& conversation) {
	const Buffer& id = conversation.id;
	//search if a conversation with this id already exists
	auto existing_conversation = std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
			[&id](const ConversationT& conversation) {
				return conversation.id == id;
			});
	//if none exists, just add the conversation
	if (existing_conversation == std::cend(this->conversations)) {
		this->conversations.push_back(std::move(conversation));
		return;
	}

	//otherwise replace the exiting one
	size_t existing_index = static_cast<size_t>(existing_conversation - std::begin(this->conversations));
	this->conversations[existing_index] = std::move(conversation);
}

void ConversationStore::remove(const ConversationT * const node) {
	if (node == nullptr) {
		return;
	}

	auto found_node = std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
			[&node](const ConversationT& conversation) {
				if (&conversation == node) {
					return true;
				}

				return false;
			});
	if (found_node != std::cend(this->conversations)) {
		this->conversations.erase(found_node);
	}
}

/*
 * Remove a conversation from the conversation store.
 *
 * The conversation is identified by it's id.
 */
void ConversationStore::remove(const Buffer& id) {
	auto found_node = std::find_if(std::cbegin(this->conversations), std::cend(this->conversations),
			[&id](const ConversationT& conversation) {
				if (conversation.id == id) {
					return true;
				}

				return false;
			});

	if (found_node != std::cend(this->conversations)) {
		this->conversations.erase(found_node);
	}
}

/*
 * Find a conversation for a given conversation ID.
 *
 * Returns nullptr if no conversation was found.
 */
ConversationT* ConversationStore::find(const Buffer& id) {
	auto node = std::find_if(std::begin(this->conversations), std::end(this->conversations),
			[&id](const ConversationT& conversation) {
				if (conversation.id == id) {
					return true;
				}

				return false;
			});

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
std::unique_ptr<Buffer> ConversationStore::list() const {
	if (this->conversations.empty()) {
		return std::unique_ptr<Buffer>();
	}

	auto list = std::make_unique<Buffer>(this->conversations.size() * CONVERSATION_ID_SIZE, 0);

	for (const auto& conversation : this->conversations) {
		size_t index = static_cast<size_t>(&conversation - &(*this->conversations.cbegin()));
		int status = list->copyFrom(
			CONVERSATION_ID_SIZE * index,
			&conversation.id,
			0,
			conversation.id.content_length);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy conversation id.");
		}

	}

	return list;
}

void ConversationStore::exportProtobuf(Conversation**& conversations, size_t& length) const {
	if (this->conversations.empty()) {
		conversations = nullptr;
		length = 0;

		return;
	}

	auto conversation_pointers = std::vector<std::unique_ptr<Conversation,ConversationDeleter>>();
	conversation_pointers.reserve(this->conversations.size());

	//export the conversations
	for (const auto& conversation : this->conversations) {
		conversation_pointers.push_back(conversation.exportProtobuf());
	}

	//allocate the output array
	conversations = throwing_zeroed_malloc<Conversation*>(this->conversations.size() * sizeof(Conversation*));
	size_t index = 0;
	for (auto&& conversation : conversation_pointers) {
		conversations[index] = conversation.release();
		index++;
	}
	length = this->conversations.size();
}

ConversationStore::ConversationStore(Conversation** const& conversations, const size_t length) {
	//check input
	if (((length > 0) && (conversations == nullptr))
			|| ((length == 0) && (conversations != nullptr))) {
		throw MolchException(INVALID_INPUT, "Invalid input to conversation_store_import");
	}

	//import all the conversations
	for (size_t i = 0; i < length; i++) {
		if (conversations[i] == nullptr) {
			throw MolchException(PROTOBUF_MISSING_ERROR, "Array of conversation has an empty element.");
		}

		this->conversations.emplace_back(*conversations[i]);
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
