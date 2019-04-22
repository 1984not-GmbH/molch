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

#include "molch/constants.h"
#include "user-store.hpp"
#include "destroyers.hpp"

namespace Molch {
	User::User(uninitialized_t uninitialized) noexcept : master_keys{uninitialized}, prekeys{uninitialized} {}

	User& User::move(User&& node) noexcept {
		this->public_signing_key = node.public_signing_key;
		this->master_keys = std::move(node.master_keys);
		this->prekeys = std::move(node.prekeys);
		this->conversations = std::move(node.conversations);

		return *this;
	}

	User::User(User&& node) noexcept : master_keys{uninitialized}, prekeys{uninitialized} {
		this->move(std::move(node));
	}

	User& User::operator=(User&& node) noexcept {
		this->move(std::move(node));
		return *this;
	}

	result<User> User::create(const std::optional<span<const std::byte>> seed) {
		User user(uninitialized);
		OUTCOME_TRY(master_keys, MasterKeys::create(seed));
		user.public_signing_key = master_keys.getSigningKey();
		user.master_keys = std::move(master_keys);
		OUTCOME_TRY(prekey_store, PrekeyStore::create());
		user.prekeys = std::move(prekey_store);

		return user;
	}

	result<User> User::import(const ProtobufCUser& user) {
		if ((user.public_signing_key == nullptr)
			|| (user.private_signing_key == nullptr)
			|| (user.public_identity_key == nullptr)
			|| (user.private_identity_key == nullptr)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "Missing keys.");
		}

		User imported_user(uninitialized);

		//master keys
		OUTCOME_TRY(master_keys, MasterKeys::import(
				*user.public_signing_key,
				*user.private_signing_key,
				*user.public_identity_key,
				*user.private_identity_key));
		imported_user.master_keys = std::move(master_keys);

		//public signing key
		OUTCOME_TRY(imported_public_signing_key, PublicSigningKey::fromSpan({user.public_signing_key->key}));
		imported_user.public_signing_key = imported_public_signing_key;

		OUTCOME_TRY(imported_conversation_store, ConversationStore::import({user.conversations, user.n_conversations}));
		imported_user.conversations = std::move(imported_conversation_store);

		OUTCOME_TRY(prekey_store, PrekeyStore::import(
				{user.prekeys, user.n_prekeys},
				{user.deprecated_prekeys, user.n_deprecated_prekeys}));
		imported_user.prekeys = std::move(prekey_store);

		return imported_user;
	}

	std::ostream& operator<<(std::ostream& stream, const User& user) {
		stream << "Public Signing Key:\n";
		stream << user.id() << "\n\n";
		stream << "\nMaster Keys:\n";
		user.masterKeys().print(stream);
		stream << "\nPrekeys:\n";
		stream << user.prekeys;
		stream << "\nConversations:\n";
		user.conversations.print(stream);

		return stream;
	}

	const PublicSigningKey& User::id() const noexcept {
		return this->public_signing_key;
	}
	const MasterKeys& User::masterKeys() const noexcept {
		return this->master_keys;
	}

	result<UserStore> UserStore::import(const span<ProtobufCUser*> users) {
		UserStore store;
		for (const auto& user : users) {
			if (user == nullptr) {
				return Error(status_type::PROTOBUF_MISSING_ERROR, "Array of users is missing a user.");
			}

			OUTCOME_TRY(imported_user, User::import(*user));
			store.add(std::move(imported_user));
		}

		return store;
	}

	void UserStore::add(User&& user) {
		const auto& public_signing_key{user.id()};
		//search if a user with this public_signing_key already exists
		auto existing_user{std::find_if(std::cbegin(this->users), std::cend(this->users),
				[public_signing_key](const User& user) {
					return user.id() == public_signing_key;
				})};
		//if none exists, just add the conversation
		if (existing_user == std::cend(this->users)) {
			this->users.emplace_back(std::move(user));
			return;
		}

		//otherwise replace the existing one
		auto existing_index{gsl::narrow_cast<size_t>(existing_user - std::cbegin(this->users))};
		this->users[existing_index] = std::move(user);
	}

	User* UserStore::find(const PublicSigningKey& public_signing_key) {
		auto user{std::find_if(std::begin(this->users), std::end(this->users),
				[public_signing_key](const User& user) {
					return user.id() == public_signing_key;
				})};
		if (user == std::end(this->users)) {
			return nullptr;
		}

		return &(*user);
	}

	Conversation* UserStore::findConversation(User*& user, const ConversationId& conversation_id) {
		Conversation* conversation{nullptr};
		auto containing_user{std::find_if(std::begin(this->users), std::end(this->users),
				[&conversation_id, &conversation](User& user) {
					conversation = user.conversations.find(conversation_id);
					return conversation != nullptr;
				})};
		if (conversation != nullptr) {
			user = &(*containing_user);
			return conversation;
		}

		user = nullptr;
		return nullptr;
	}

	result<Buffer> UserStore::list() {
		Buffer list{this->users.size() * PUBLIC_MASTER_KEY_SIZE, 0};

		for (const auto& user : this->users) {
			auto index{gsl::narrow_cast<size_t>(&user - &(*std::cbegin(this->users)))};
			OUTCOME_TRY(list.copyFromRaw(
				PUBLIC_MASTER_KEY_SIZE * index,
				user.id().data(),
				0,
				user.id().size()));
		}

		return list;
	}

	void UserStore::remove(const User* const user) {
		if (user == nullptr) {
			return;
		}

		auto found_node{std::find_if(std::cbegin(this->users), std::cend(this->users),
				[user](const User& node) {
					return &node == user;
				})};
		if (found_node != std::cend(this->users)) {
			this->users.erase(found_node);
		}
	}

	void UserStore::remove(const PublicSigningKey& public_signing_key) {
		auto found_node{std::find_if(std::cbegin(this->users), std::cend(this->users),
				[public_signing_key](const User& user) {
					return user.id() == public_signing_key;
				})};

		if (found_node != std::cend(this->users)) {
			this->users.erase(found_node);
		}
	}

	void UserStore::clear() {
		this->users.clear();
	}

	result<ProtobufCUser*> User::exportProtobuf(Arena& arena) const {
		auto user{protobuf_create<ProtobufCUser>(arena)};

		OUTCOME_TRY(exported_master_keys, this->master_keys.exportProtobuf(arena));
		user->public_signing_key = exported_master_keys.public_signing_key;
		user->private_signing_key = exported_master_keys.private_signing_key;
		user->public_identity_key = exported_master_keys.public_identity_key;
		user->private_identity_key = exported_master_keys.private_identity_key;

		//export the conversation store
		outcome_protobuf_array_arena_export(arena, user, conversations, this->conversations);

		//export the prekeys
		OUTCOME_TRY(exported_prekeys, this->prekeys.exportProtobuf(arena));
		user->prekeys = exported_prekeys.keypairs.data();
		user->n_prekeys = exported_prekeys.keypairs.size();
		user->deprecated_prekeys = exported_prekeys.deprecated_keypairs.data();
		user->n_deprecated_prekeys = exported_prekeys.deprecated_keypairs.size();

		return user;
	}

	result<span<ProtobufCUser*>> UserStore::exportProtobuf(Arena& arena) const {
		if (this->users.empty()) {
			return {nullptr, static_cast<size_t>(0)};
		}

		//export the conversations
		auto users_array{arena.allocate<ProtobufCUser*>(this->users.size())};
		size_t index{0};
		for (const auto& user : this->users) {
			OUTCOME_TRY(exported_user, user.exportProtobuf(arena));
			users_array[index] = exported_user;
			index++;
		}
		return {users_array, this->users.size()};
	}

	size_t UserStore::size() const {
		return this->users.size();
	}
}
