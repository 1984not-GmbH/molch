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
#include <exception>
#include <iterator>

#include "molch-exception.hpp"
#include "constants.h"
#include "user-store.hpp"
#include "destroyers.hpp"

UserStoreNode& UserStoreNode::move(UserStoreNode&& node) {
	if (this->public_signing_key.cloneFrom(&node.public_signing_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to clone public signing key.");
	}
	this->master_keys = std::move(node.master_keys);
	this->prekeys = std::move(node.prekeys);
	this->conversations = std::move(node.conversations);

	return *this;
}

UserStoreNode::UserStoreNode(UserStoreNode&& node) {
	this->move(std::move(node));
}

UserStoreNode& UserStoreNode::operator=(UserStoreNode&& node) {
	return this->move(std::move(node));
}

void UserStoreNode::exportPublicKeys(
		Buffer * const public_signing_key, //output, optional, can be nullptr
		Buffer * const public_identity_key) { //output, optional, can be nullptr
	//get the public keys
	if (public_signing_key != nullptr) {
		this->master_keys.getSigningKey(*public_signing_key);
	}
	if (public_identity_key != nullptr) {
		this->master_keys.getIdentityKey(*public_identity_key);
	}
}

UserStoreNode::UserStoreNode(
		const Buffer& seed,
		Buffer * const public_signing_key, //output, optional, can be nullptr
		Buffer * const public_identity_key//output, optional, can be nullptr
		) : master_keys(seed) {
	this->exportPublicKeys(public_signing_key, public_identity_key);
	this->master_keys.getSigningKey(this->public_signing_key);
}

UserStoreNode::UserStoreNode(
		Buffer * const public_signing_key, //output, optional, can be nullptr
		Buffer * const public_identity_key) { //output, optional, can be nullptr
	this->exportPublicKeys(public_signing_key, public_identity_key);
	this->master_keys.getSigningKey(this->public_signing_key);
}

UserStoreNode::UserStoreNode(const User& user) {
	if ((user.public_signing_key == nullptr)
			|| (user.private_signing_key == nullptr)
			|| (user.public_identity_key == nullptr)
			|| (user.private_identity_key == nullptr)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "Missing keys.");
	}

	//master keys
	this->master_keys = MasterKeys(
		*user.public_signing_key,
		*user.private_signing_key,
		*user.public_identity_key,
		*user.private_identity_key);

	//public signing key
	if (this->public_signing_key.cloneFromRaw(user.public_signing_key->key.data, user.public_signing_key->key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public signing key.");
	}

	this->conversations = ConversationStore(user.conversations, user.n_conversations);

	this->prekeys = PrekeyStore(
		user.prekeys,
		user.n_prekeys,
		user.deprecated_prekeys,
		user.n_deprecated_prekeys);
}

std::ostream& UserStoreNode::print(std::ostream& stream) const {
	stream << "Public Signing Key:\n";
	stream << this->public_signing_key.toHex() + "\n\n";
	stream << "\nMaster Keys:\n";
	this->master_keys.print(stream);
	stream << "\nPrekeys:\n";
	this->prekeys.print(stream);
	stream << "\nConversations:\n";
	this->conversations.print(stream);

	return stream;
}

UserStore::UserStore(User ** const& users, const size_t users_length) {
	//check input
	if (((users_length == 0) && (users != nullptr))
			|| ((users_length > 0) && (users == nullptr))) {
		throw MolchException(INVALID_INPUT, "Invalid input to user_store_import.");
	}

	for (size_t i = 0; i < users_length; i++) {
		if (users[i] == nullptr) {
			throw MolchException(PROTOBUF_MISSING_ERROR, "Array of users is missing a user.");
		}

		this->add(UserStoreNode(*users[i]));
	}
}

void UserStore::add(UserStoreNode&& user) {
	const Buffer& public_signing_key = user.public_signing_key;
	//search if a user with this public_signing_key already exists
	auto existing_user = std::find_if(std::cbegin(this->users), std::cend(this->users),
			[public_signing_key](const UserStoreNode& user) {
				return user.public_signing_key == public_signing_key;
			});
	//if none exists, just add the conversation
	if (existing_user == std::cend(this->users)) {
		this->users.emplace_back(std::move(user));
		return;
	}

	//otherwise replace the existing one
	size_t existing_index = static_cast<size_t>(existing_user - std::cbegin(this->users));
	this->users[existing_index] = std::move(user);
}

UserStoreNode* UserStore::find(const Buffer& public_signing_key) {
	if (!public_signing_key.contains(PUBLIC_MASTER_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to UserStore::find.");
	}

	auto user = std::find_if(std::begin(this->users), std::end(this->users),
			[public_signing_key](const UserStoreNode& user) {
				return user.public_signing_key == public_signing_key;
			});
	if (user == std::end(this->users)) {
		return nullptr;
	}

	return &(*user);
}

ConversationT* UserStore::findConversation(UserStoreNode*& user, const Buffer& conversation_id) {
	if (!conversation_id.contains(CONVERSATION_ID_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to UserStore::findConversation.");
	}

	ConversationT* conversation = nullptr;
	auto containing_user = std::find_if(std::begin(this->users), std::end(this->users),
			[&conversation_id, &conversation](UserStoreNode& user) {
				conversation = user.conversations.find(conversation_id);
				return conversation != nullptr;
			});
	if (conversation != nullptr) {
		user = &(*containing_user);
		return conversation;
	}

	user = nullptr;
	return nullptr;
}

std::unique_ptr<Buffer> UserStore::list() {
	auto list = std::make_unique<Buffer>(this->users.size() * PUBLIC_MASTER_KEY_SIZE, 0);

	for (const auto& user : this->users) {
		size_t index = static_cast<size_t>(&user - &(*std::cbegin(this->users)));
		int status = list->copyFrom(
			CONVERSATION_ID_SIZE * index,
			&user.public_signing_key,
			0,
			user.public_signing_key.content_length);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy public signing key.");
		}

	}

	return list;
}

void UserStore::remove(const UserStoreNode* const node) {
	if (node == nullptr) {
		return;
	}

	auto found_node = std::find_if(std::cbegin(this->users), std::cend(this->users),
			[node](const UserStoreNode& user) {
				if (&user == node) {
					return true;
				}

				return false;
			});
	if (found_node != std::cend(this->users)) {
		this->users.erase(found_node);
	}
}

void UserStore::remove(const Buffer& public_signing_key) {
	auto found_node = std::find_if(std::cbegin(this->users), std::cend(this->users),
			[public_signing_key](const UserStoreNode& user) {
				return user.public_signing_key == public_signing_key;
			});

	if (found_node != std::cend(this->users)) {
		this->users.erase(found_node);
	}
}

void UserStore::clear() {
	this->users.clear();
}

std::unique_ptr<User,UserDeleter> UserStoreNode::exportProtobuf() {
	auto user = std::unique_ptr<User,UserDeleter>(throwing_zeroed_malloc<User>(sizeof(User)));
	user__init(user.get());

	//export master keys
	std::unique_ptr<Key,KeyDeleter> public_signing_key;
	std::unique_ptr<Key,KeyDeleter> private_signing_key;
	std::unique_ptr<Key,KeyDeleter> public_identity_key;
	std::unique_ptr<Key,KeyDeleter> private_identity_key;
	this->master_keys.exportProtobuf(
		public_signing_key,
		private_signing_key,
		public_identity_key,
		private_identity_key);
	user->public_signing_key = public_signing_key.release();
	user->private_signing_key = private_signing_key.release();
	user->public_identity_key = public_identity_key.release();
	user->private_identity_key = private_identity_key.release();

	//export the conversation store
	this->conversations.exportProtobuf(user->conversations, user->n_conversations);

	//export the prekeys
	this->prekeys.exportProtobuf(
		user->prekeys,
		user->n_prekeys,
		user->deprecated_prekeys,
		user->n_deprecated_prekeys);

	return user;
}

void UserStore::exportProtobuf(User**& users, size_t& users_length) {
	if (this->users.empty()) {
		users = nullptr;
		users_length = 0;

		return;
	}

	auto user_pointers = std::vector<std::unique_ptr<User,UserDeleter>>();
	user_pointers.reserve(this->users.size());

	//export the conversations
	for (auto&& user : this->users) {
		user_pointers.push_back(user.exportProtobuf());
	}

	//allocate the output array
	users = throwing_zeroed_malloc<User*>(this->users.size() * sizeof(User*));
	size_t index = 0;
	for (auto&& user : user_pointers) {
		users[index] = user.release();
		index++;
	}
	users_length = this->users.size();
}

size_t UserStore::size() const {
	return this->users.size();
}

std::ostream& UserStore::print(std::ostream& stream) const {
	stream << "Users: [\n";
	for (auto&& user : this->users) {
		user.print(stream) << ",\n";
	}
	stream << "]\n";

	return stream;
}
