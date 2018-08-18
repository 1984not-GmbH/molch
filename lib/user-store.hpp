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

#ifndef LIB_USER_STORE_H
#define LIB_USER_STORE_H

#include <sodium.h>
#include <memory>
#include <ostream>

#include "constants.h"
#include "buffer.hpp"
#include "conversation-store.hpp"
#include "prekey-store.hpp"
#include "master-keys.hpp"
#include "protobuf.hpp"
#include "gsl.hpp"
#include "protobuf-arena.hpp"

//The user store stores a list of all users identified by their public keys

namespace Molch {
	class User {
	private:
		PublicSigningKey public_signing_key;
		MasterKeys master_keys;

		User& move(User&& node) noexcept;

		User() = delete;
		User(uninitialized_t uninitialized) noexcept;

	public:
		PrekeyStore prekeys;
		ConversationStore conversations;

		/*
		 * Create a new user.
		 *
		 * The seed is optional an can be used to add entropy in addition
		 * to the entropy provided by the OS. IMPORTANT: Don't put entropy in
		 * here, that was generated by the OSs CPRNG!
		 */
		static result<User> create(const std::optional<span<const std::byte>> seed = std::nullopt);

		User(const User& node) = delete;
		User(User&& node) noexcept;

		User& operator=(const User& node) = delete;
		User& operator=(User&& node) noexcept;

		/*! Import a user from a Protobuf-C struct
		 * \param user The struct to import from.
		 */
		static result<User> import(const ProtobufCUser& user);

		result<ProtobufCUser*> exportProtobuf(Arena& arena) const;

		const PublicSigningKey& id() const noexcept;
		const MasterKeys& masterKeys() const noexcept;
	};

	std::ostream& operator<<(std::ostream& stream, const User& user);

	//header of the user store
	class UserStore {
	private:
			std::vector<User> users;

	public:
		UserStore() = default;

		/*! Import a user store from an array of Protobuf-C structs
		 * \param users The array to import from.
		 */
		static result<UserStore> import(const span<ProtobufCUser*> users);

		UserStore(const UserStore& store) = delete;
		UserStore(UserStore&& store) = default;

		UserStore& operator=(const UserStore& store) = delete;
		UserStore& operator=(UserStore&& store) = default;

		void add(User&& user);

		/*
		 * Find a user with a given public signing key.
		 *
		 * Returns nullptr if no user was found.
		 */
		User* find(const PublicSigningKey& public_signing_key);

		/*
		 * Find a conversation with a given public signing key.
		 *
		 * return nullptr if no conversation was found.
		 */
		Conversation* findConversation(User*& user, const ConversationId& conversation_id);

		/*
		 * List all of the users.
		 *
		 * Returns a buffer containing a list of all the public
		 * signing keys of the user.
		 */
		result<Buffer> list();

		void remove(const PublicSigningKey& public_signing_key);
		void remove(const User* const user);

		void clear();

		/*! Export a user store to an array of Protobuf-C structs */
		result<span<ProtobufCUser*>> exportProtobuf(Arena& arena) const;

		size_t size() const;
	};
}

#endif
