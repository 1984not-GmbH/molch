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

#include "conversation-store.h"
#include "destroyers.h"

size_t ConversationStore::getLength() noexcept {
	return this->length;
}

/*
 * Init new conversation store.
 */
void ConversationStore::init() noexcept {
	this->length = 0;
	this->head = nullptr;
	this->tail = nullptr;
}

/*
 * add a conversation to the conversation store.
 */
return_status ConversationStore::add(conversation_t * const conversation) noexcept {

	return_status status = return_status_init();

	if (conversation == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_add");
	}

	if (this->head == nullptr) { //first conversation in the list
		conversation->previous = nullptr;
		conversation->next = nullptr;
		this->head = conversation;
		this->tail = conversation;

		//update length
		this->length++;

		goto cleanup;
	}

	//add the new conversation to the tail of the list
	this->tail->next = conversation;
	conversation->previous = this->tail;
	conversation->next = nullptr;
	this->tail = conversation;

	//update length
	this->length++;

cleanup:

	return status;
}

/*
 * Remove a conversation from the conversation_store.
 */
void ConversationStore::remove(conversation_t * const node) noexcept {
	if (node == nullptr) {
		return;
	}


	if ((node->next != nullptr) && (node != this->tail)) { //node is not the tail
		node->next->previous = node->previous;
	} else {
		this->tail = node->previous;
	}

	if ((node->previous != nullptr) && (node != this->head)) { //node is not the head
		node->previous->next = node->next;
	} else {
		this->head = node->next;
	}

	this->length--;

	conversation_destroy(node);
}

/*
 * Remove a conversation from the conversation store.
 *
 * The conversation is identified by it's id.
 */
void ConversationStore::removeById(const Buffer& id) noexcept {
	conversation_t *node = nullptr;
	node = this->findNode(id);
	if (node == nullptr) {
		return;
	}

	this->remove(node);
}

/*
 * Find a conversation for a given conversation ID.
 *
 * Returns nullptr if no conversation was found.
 */
conversation_t* ConversationStore::findNode(const Buffer& id) noexcept {
	conversation_t* conversation = nullptr;
	size_t index = 0;
	for (conversation = this->head; (index < this->length) && (conversation != NULL); conversation = conversation->next, index++) {
		if (conversation->id.compare(&id) == 0) {
			break;
		}
	}

	return conversation;
}

/*
 * Remove all entries from a conversation store.
 */
void ConversationStore::clear() noexcept {
	while (this->length > 0) {
		this->remove(this->tail);
	}
}

/*
 * Create a list of conversations (one buffer filled with the conversation ids.
 *
 * Returns nullptr if empty.
 */
return_status ConversationStore::list(Buffer*& list) noexcept {
	return_status status = return_status_init();
	conversation_t *conversation = nullptr;
	size_t index = 0;

	if (this->length == 0) {
		list = nullptr;
		goto cleanup;
	}

	list = Buffer::create(this->length * CONVERSATION_ID_SIZE, 0);
	THROW_on_failed_alloc(list);
	//copy all the id's
	for (conversation = this->head; (index < this->getLength()) && (conversation != nullptr); index++, conversation = conversation->next) {
		int status_int = list->copyFrom(
			CONVERSATION_ID_SIZE * index,
			&conversation->id,
			0,
			conversation->id.content_length);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy conversation id.");
		}
	}

cleanup:
	on_error {
		buffer_destroy_and_null_if_valid(list);
	}

	return status;
}

return_status ConversationStore::exportConversationStore(Conversation**& conversations, size_t& length) const noexcept {
	return_status status = return_status_init();

	if (this->length > 0) {
		//allocate the array of conversations
		conversations = reinterpret_cast<Conversation**>(zeroed_malloc(this->length * sizeof(Conversation*)));
		THROW_on_failed_alloc(conversations);
		std::fill(conversations, conversations + this->length, nullptr);
	} else {
		conversations = nullptr;
	}

	//export the conversations
	{
		conversation_t *node = this->head;
		for (size_t i = 0; (i < this->length) && (node != nullptr); i++, node = node->next) {
			status = conversation_export(node, &conversations[i]);
			THROW_on_error(EXPORT_ERROR, "Failed to export conversation.");
		}
	}

	length = this->length;

cleanup:
	on_error {
		if (conversations != nullptr) {
			for (size_t i = 0; i < this->length; i++) {
				if (conversations[i] != nullptr) {
					conversation__free_unpacked(conversations[i], &protobuf_c_allocators);
					conversations[i] = nullptr;
				}
			}
		}
	}

	return status;
}

return_status ConversationStore::import(Conversation ** const conversations, const size_t length) noexcept {
	return_status status = return_status_init();

	conversation_t *conversation = nullptr;

	//check input
	if (((length > 0) && (conversations == nullptr))
			|| ((length == 0) && (conversations != nullptr))) {
		THROW(INVALID_INPUT, "Invalid input to conversation_store_import");
	}

	this->init();

	//import all the conversations
	for (size_t i = 0; i < length; i++) {
		status = conversation_import(
			&conversation,
			conversations[i]);
		THROW_on_error(IMPORT_ERROR, "Failed to import conversation.");

		status = this->add(conversation);
		THROW_on_error(ADDITION_ERROR, "Failed to add conversation to conversation store.");
		conversation = nullptr;
	}

cleanup:
	on_error {
		if (conversation != nullptr) {
			conversation_destroy(conversation);
			conversation = nullptr;
		}

		this->clear();
	}

	return status;
}

