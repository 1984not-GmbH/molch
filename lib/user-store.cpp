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

namespace Molch {
	User& User::move(User&& node) {
		this->public_signing_key = node.public_signing_key;
		this->master_keys = std::move(node.master_keys);
		this->prekeys = std::move(node.prekeys);
		this->conversations = std::move(node.conversations);

		return *this;
	}

	User::User(User&& node) {
		this->move(std::move(node));
	}

	User& User::operator=(User&& node) {
		return this->move(std::move(node));
	}

	void User::exportPublicKeys(
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key) { //output, optional, can be nullptr
		//get the public keys
		if (public_signing_key != nullptr) {
			this->master_keys.getSigningKey(*public_signing_key);
		}
		if (public_identity_key != nullptr) {
			this->master_keys.getIdentityKey(*public_identity_key);
		}
	}

	User::User(
			const Buffer& seed,
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key//output, optional, can be nullptr
			) : master_keys(seed) {
		this->exportPublicKeys(public_signing_key, public_identity_key);
		this->master_keys.getSigningKey(this->public_signing_key);
	}

	User::User(
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key) { //output, optional, can be nullptr
		this->exportPublicKeys(public_signing_key, public_identity_key);
		this->master_keys.getSigningKey(this->public_signing_key);
	}

	User::User(const ProtobufCUser& user) {
		if ((user.public_signing_key == nullptr)
				|| (user.private_signing_key == nullptr)
				|| (user.public_identity_key == nullptr)
				|| (user.private_identity_key == nullptr)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Missing keys.");
		}

		//master keys
		this->master_keys = MasterKeys(
			*user.public_signing_key,
			*user.private_signing_key,
			*user.public_identity_key,
			*user.private_identity_key);

		//public signing key
		this->public_signing_key.set(user.public_signing_key->key.data, user.public_signing_key->key.len);

		this->conversations = ConversationStore(user.conversations, user.n_conversations);

		this->prekeys = PrekeyStore(
			user.prekeys,
			user.n_prekeys,
			user.deprecated_prekeys,
			user.n_deprecated_prekeys);
	}

	std::ostream& User::print(std::ostream& stream) const {
		stream << "Public Signing Key:\n";
		this->public_signing_key.printHex(stream) << "\n\n";
		stream << "\nMaster Keys:\n";
		this->master_keys.print(stream);
		stream << "\nPrekeys:\n";
		this->prekeys.print(stream);
		stream << "\nConversations:\n";
		this->conversations.print(stream);

		return stream;
	}

	UserStore::UserStore(ProtobufCUser ** const& users, const size_t users_length) {
		//check input
		if (((users_length == 0) && (users != nullptr))
				|| ((users_length > 0) && (users == nullptr))) {
			throw Exception(INVALID_INPUT, "Invalid input to user_store_import.");
		}

		for (size_t i = 0; i < users_length; i++) {
			if (users[i] == nullptr) {
				throw Exception(PROTOBUF_MISSING_ERROR, "Array of users is missing a user.");
			}

			this->add(User(*users[i]));
		}
	}

	void UserStore::add(User&& user) {
		const PublicSigningKey& public_signing_key = user.public_signing_key;
		//search if a user with this public_signing_key already exists
		auto existing_user = std::find_if(std::cbegin(this->users), std::cend(this->users),
				[public_signing_key](const User& user) {
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

	User* UserStore::find(const PublicSigningKey& public_signing_key) {
		if (public_signing_key.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to UserStore::find.");
		}

		auto user = std::find_if(std::begin(this->users), std::end(this->users),
				[public_signing_key](const User& user) {
					return user.public_signing_key == public_signing_key;
				});
		if (user == std::end(this->users)) {
			return nullptr;
		}

		return &(*user);
	}

	Conversation* UserStore::findConversation(User*& user, const Key<CONVERSATION_ID_SIZE,KeyType::Key>& conversation_id) {
		if (conversation_id.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to UserStore::findConversation.");
		}

		Conversation* conversation = nullptr;
		auto containing_user = std::find_if(std::begin(this->users), std::end(this->users),
				[&conversation_id, &conversation](User& user) {
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

	Buffer UserStore::list() {
		Buffer list(this->users.size() * PUBLIC_MASTER_KEY_SIZE, 0);

		for (const auto& user : this->users) {
			size_t index = static_cast<size_t>(&user - &(*std::cbegin(this->users)));
			list.copyFromRaw(
				PUBLIC_MASTER_KEY_SIZE * index,
				user.public_signing_key.data(),
				0,
				user.public_signing_key.size());
		}

		return list;
	}

	void UserStore::remove(const User* const node) {
		if (node == nullptr) {
			return;
		}

		auto found_node = std::find_if(std::cbegin(this->users), std::cend(this->users),
				[node](const User& user) {
					if (&user == node) {
						return true;
					}

					return false;
				});
		if (found_node != std::cend(this->users)) {
			this->users.erase(found_node);
		}
	}

	void UserStore::remove(const PublicSigningKey& public_signing_key) {
		auto found_node = std::find_if(std::cbegin(this->users), std::cend(this->users),
				[public_signing_key](const User& user) {
					return user.public_signing_key == public_signing_key;
				});

		if (found_node != std::cend(this->users)) {
			this->users.erase(found_node);
		}
	}

	void UserStore::clear() {
		this->users.clear();
	}

	ProtobufCUser* User::exportProtobuf(ProtobufPool& pool) const {
		auto user = pool.allocate<ProtobufCUser>(1);
		user__init(user);

		this->master_keys.exportProtobuf(
			pool,
			user->public_signing_key,
			user->private_signing_key,
			user->public_identity_key,
			user->private_identity_key);

		//export the conversation store
		this->conversations.exportProtobuf(
				pool,
				user->conversations,
				user->n_conversations);

		//export the prekeys
		this->prekeys.exportProtobuf(
			pool,
			user->prekeys,
			user->n_prekeys,
			user->deprecated_prekeys,
			user->n_deprecated_prekeys);

		return user;
	}

	void UserStore::exportProtobuf(ProtobufPool& pool, ProtobufCUser**& users, size_t& users_length) const {
		if (this->users.empty()) {
			users = nullptr;
			users_length = 0;

			return;
		}

		//export the conversations
		users = pool.allocate<ProtobufCUser*>(this->users.size());
		size_t index = 0;
		for (auto&& user : this->users) {
			users[index] = user.exportProtobuf(pool);
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
}
