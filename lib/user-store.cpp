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
	User& User::move(User&& node) noexcept {
		this->public_signing_key = node.public_signing_key;
		this->master_keys = std::move(node.master_keys);
		this->prekey_store = std::move(node.prekey_store);
		this->conversation_store = std::move(node.conversation_store);

		return *this;
	}

	User::User(User&& node) noexcept {
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

	User::User(
			const span<const std::byte> seed,
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key//output, optional, can be nullptr
			) : master_keys(seed) {
		this->exportPublicKeys(public_signing_key, public_identity_key);
		this->public_signing_key = this->master_keys.getSigningKey();
	}

	User::User(
			PublicSigningKey * const public_signing_key, //output, optional, can be nullptr
			PublicKey * const public_identity_key) { //output, optional, can be nullptr
		this->exportPublicKeys(public_signing_key, public_identity_key);
		this->public_signing_key = this->master_keys.getSigningKey();
	}

	User::User(const ProtobufCUser& user) {
		if ((user.public_signing_key == nullptr)
				|| (user.private_signing_key == nullptr)
				|| (user.public_identity_key == nullptr)
				|| (user.private_identity_key == nullptr)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Missing keys."};
		}

		//master keys
		this->master_keys = MasterKeys{
			*user.public_signing_key,
			*user.private_signing_key,
			*user.public_identity_key,
			*user.private_identity_key};

		//public signing key
		this->public_signing_key.set({
				uchar_to_byte(user.public_signing_key->key.data),
				user.public_signing_key->key.len});

		this->conversation_store = ConversationStore{{user.conversations, user.n_conversations}};

		this->prekey_store = PrekeyStore{
			{user.prekeys, user.n_prekeys},
			{user.deprecated_prekeys, user.n_deprecated_prekeys}};
	}

	std::ostream& User::print(std::ostream& stream) const {
		stream << "Public Signing Key:\n";
		this->public_signing_key.printHex(stream) << "\n\n";
		stream << "\nMaster Keys:\n";
		this->master_keys.print(stream);
		stream << "\nPrekeys:\n";
		this->prekey_store.print(stream);
		stream << "\nConversations:\n";
		this->conversation_store.print(stream);

		return stream;
	}

	const PublicSigningKey& User::id() const {
		return this->public_signing_key;
	}
	const MasterKeys& User::masterKeys() const {
		return this->master_keys;
	}
	PrekeyStore& User::prekeys() {
		return this->prekey_store;
	}
	ConversationStore& User::conversations() {
		return this->conversation_store;
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
					conversation = user.conversation_store.find(conversation_id);
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
			list.copyFromRaw(
				PUBLIC_MASTER_KEY_SIZE * index,
				user.public_signing_key.data(),
				0,
				user.public_signing_key.size());
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

	ProtobufCUser* User::exportProtobuf(Arena& pool) const {
		auto user{pool.allocate<ProtobufCUser>(1)};
		user__init(user);

		this->master_keys.exportProtobuf(
			pool,
			user->public_signing_key,
			user->private_signing_key,
			user->public_identity_key,
			user->private_identity_key);

		//export the conversation store
		auto exported_conversations{this->conversation_store.exportProtobuf(pool)};
		user->conversations = exported_conversations.data();
		user->n_conversations = exported_conversations.size();

		//export the prekeys
		span<ProtobufCPrekey*> exported_prekeys;
		span<ProtobufCPrekey*> exported_deprecated_prekeys;
		this->prekey_store.exportProtobuf(
			pool,
			exported_prekeys,
			exported_deprecated_prekeys);
		user->prekeys = exported_prekeys.data();
		user->n_prekeys = exported_prekeys.size();
		user->deprecated_prekeys = exported_deprecated_prekeys.data();
		user->n_deprecated_prekeys = exported_deprecated_prekeys.size();

		return user;
	}

	span<ProtobufCUser*> UserStore::exportProtobuf(Arena& pool) const {
		if (this->users.empty()) {
			return {nullptr, static_cast<size_t>(0)};
		}

		//export the conversations
		auto users_array{pool.allocate<ProtobufCUser*>(this->users.size())};
		size_t index{0};
		for (const auto& user : this->users) {
			users_array[index] = user.exportProtobuf(pool);
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
