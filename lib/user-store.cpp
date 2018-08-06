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

#include "constants.h"
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

	User::User(User&& node) noexcept : master_keys{uninitialized_t::uninitialized}, prekeys{uninitialized_t::uninitialized} {
		this->move(std::move(node));
	}

	User& User::operator=(User&& node) noexcept {
		this->move(std::move(node));
		return *this;
	}

	void User::exportPublicKeys(
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key) { //output, optional, can be nullptr
		//get the public keys
		if (public_signing_key != nullptr) {
			*public_signing_key = this->master_keys.getSigningKey();
		}
		if (public_identity_key != nullptr) {
			*public_identity_key = this->master_keys.getIdentityKey();
		}
	}

	result<User> User::create(const std::optional<span<const std::byte>> seed) {
		User user(uninitialized_t::uninitialized);
		OUTCOME_TRY(master_keys, MasterKeys::create(seed));
		user.master_keys = std::move(master_keys);
		OUTCOME_TRY(prekey_store, PrekeyStore::create());
		user.prekeys = std::move(prekey_store);
		user.public_signing_key = master_keys.getSigningKey();

		return user;
	}

	User::User(const ProtobufCUser& user) : master_keys{uninitialized_t::uninitialized}, prekeys{uninitialized_t::uninitialized} {
		if ((user.public_signing_key == nullptr)
				|| (user.private_signing_key == nullptr)
				|| (user.public_identity_key == nullptr)
				|| (user.private_identity_key == nullptr)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Missing keys."};
		}

		TRY_WITH_RESULT(prekey_store, PrekeyStore::create());
		this->prekeys = std::move(prekey_store.value());

		//master keys
		TRY_WITH_RESULT(master_keys, MasterKeys::import(
				*user.public_signing_key,
				*user.private_signing_key,
				*user.public_identity_key,
				*user.private_identity_key));
		this->master_keys = std::move(master_keys.value());

		//public signing key
		this->public_signing_key.set({
				uchar_to_byte(user.public_signing_key->key.data),
				user.public_signing_key->key.len});

		this->conversations = ConversationStore{{user.conversations, user.n_conversations}};

		TRY_WITH_RESULT(imported_prekey_store, PrekeyStore::import(
			{user.prekeys, user.n_prekeys},
			{user.deprecated_prekeys, user.n_deprecated_prekeys}));
		this->prekeys = std::move(imported_prekey_store.value());
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

	const PublicSigningKey& User::id() const noexcept {
		return this->public_signing_key;
	}
	const MasterKeys& User::masterKeys() const noexcept {
		return this->master_keys;
	}

	UserStore::UserStore(const span<ProtobufCUser*> users) {
		for (const auto& user : users) {
			if (user == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Array of users is missing a user."};
			}

			this->add({*user});
		}
	}

	void UserStore::add(User&& user) {
		const auto& public_signing_key{user.public_signing_key};
		//search if a user with this public_signing_key already exists
		auto existing_user{std::find_if(std::cbegin(this->users), std::cend(this->users),
				[public_signing_key](const User& user) {
					return user.public_signing_key == public_signing_key;
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
		Expects(!public_signing_key.empty);

		auto user{std::find_if(std::begin(this->users), std::end(this->users),
				[public_signing_key](const User& user) {
					return user.public_signing_key == public_signing_key;
				})};
		if (user == std::end(this->users)) {
			return nullptr;
		}

		return &(*user);
	}

	Conversation* UserStore::findConversation(User*& user, const Key<CONVERSATION_ID_SIZE,KeyType::Key>& conversation_id) {
		Expects(!conversation_id.empty);

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

	Buffer UserStore::list() {
		Buffer list{this->users.size() * PUBLIC_MASTER_KEY_SIZE, 0};

		for (const auto& user : this->users) {
			auto index{gsl::narrow_cast<size_t>(&user - &(*std::cbegin(this->users)))};
			TRY_VOID(list.copyFromRaw(
				PUBLIC_MASTER_KEY_SIZE * index,
				user.public_signing_key.data(),
				0,
				user.public_signing_key.size()));
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
					return user.public_signing_key == public_signing_key;
				})};

		if (found_node != std::cend(this->users)) {
			this->users.erase(found_node);
		}
	}

	void UserStore::clear() {
		this->users.clear();
	}

	ProtobufCUser* User::exportProtobuf(Arena& arena) const {
		protobuf_arena_create(arena, ProtobufCUser, user);

		TRY_WITH_RESULT(exported_master_keys_result, this->master_keys.exportProtobuf(arena));
		auto& exported_master_keys{exported_master_keys_result.value()};
        user->public_signing_key = exported_master_keys.public_signing_key;
        user->private_signing_key = exported_master_keys.private_signing_key;
        user->public_identity_key = exported_master_keys.public_identity_key;
        user->private_identity_key = exported_master_keys.private_identity_key;

		//export the conversation store
		protobuf_array_arena_export(arena, user, conversations, this->conversations);

		//export the prekeys
		TRY_WITH_RESULT(exported_prekeys_result, this->prekeys.exportProtobuf(arena));
		const auto& exported_prekeys{exported_prekeys_result.value()};
		user->prekeys = exported_prekeys.keypairs.data();
		user->n_prekeys = exported_prekeys.keypairs.size();
		user->deprecated_prekeys = exported_prekeys.deprecated_keypairs.data();
		user->n_deprecated_prekeys = exported_prekeys.deprecated_keypairs.size();

		return user;
	}

	span<ProtobufCUser*> UserStore::exportProtobuf(Arena& arena) const {
		if (this->users.empty()) {
			return {nullptr, static_cast<size_t>(0)};
		}

		//export the conversations
		auto users_array{arena.allocate<ProtobufCUser*>(this->users.size())};
		size_t index{0};
		for (const auto& user : this->users) {
			users_array[index] = user.exportProtobuf(arena);
			index++;
		}
		return {users_array, this->users.size()};
	}

	size_t UserStore::size() const {
		return this->users.size();
	}

	std::ostream& UserStore::print(std::ostream& stream) const {
		stream << "Users: [\n";
		for (const auto& user : this->users) {
			user.print(stream) << ",\n";
		}
		stream << "]\n";

		return stream;
	}
}
