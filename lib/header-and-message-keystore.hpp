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

#ifndef LIB_HEADER_AND_MESSAGE_KEY_STORE_H
#define LIB_HEADER_AND_MESSAGE_KEY_STORE_H

#include <sodium.h>
#include <vector>
#include <ostream>

#include "constants.h"
#include "buffer.hpp"
#include "return-status.hpp"
#include "sodium-wrappers.hpp"
#include "protobuf.hpp"
#include "key.hpp"
#include "time.hpp"

namespace Molch {
	class HeaderAndMessageKey {
	private:
		void fill(const EmptyableHeaderKey& header_key, const MessageKey& message_key, const seconds expiration_date) noexcept;

		HeaderAndMessageKey& copy(const HeaderAndMessageKey& node) noexcept;
		HeaderAndMessageKey& move(HeaderAndMessageKey&& node) noexcept;

		MessageKey message_key;
		EmptyableHeaderKey header_key;
		seconds expiration_date{0};

	public:
		HeaderAndMessageKey() = delete;
		HeaderAndMessageKey(uninitialized_t uninitialized) noexcept;
		HeaderAndMessageKey(const EmptyableHeaderKey& header_key, const MessageKey& message_key) noexcept;
		HeaderAndMessageKey(const EmptyableHeaderKey& header_key, const MessageKey& message_key, const seconds expiration_date) noexcept;
		/* copy and move constructors */
		HeaderAndMessageKey(const HeaderAndMessageKey& node) noexcept;
		HeaderAndMessageKey(HeaderAndMessageKey&& node) noexcept;
		static result<HeaderAndMessageKey> import(const ProtobufCKeyBundle& key_bundle) noexcept;

		/* copy and move assignment operators */
		HeaderAndMessageKey& operator=(const HeaderAndMessageKey& node) noexcept;
		HeaderAndMessageKey& operator=(HeaderAndMessageKey&& node) noexcept;

		const MessageKey& messageKey() const noexcept;
		const EmptyableHeaderKey& headerKey() const noexcept;
		seconds expirationDate() const noexcept;

		result<ProtobufCKeyBundle*> exportProtobuf(Arena& arena) const;
	};

	std::ostream& operator<<(std::ostream& stream, const HeaderAndMessageKey& header_and_message_key);

	static constexpr size_t header_and_message_store_maximum_keys{1000};
	static constexpr seconds header_and_message_store_maximum_age{1_months};

	//header of the key store
	class HeaderAndMessageKeyStore {
	private:
		//Vector of Header and message keys, sorted in ascending order by expiration date
		std::vector<HeaderAndMessageKey,SodiumAllocator<HeaderAndMessageKey>> key_storage;

	public:
		HeaderAndMessageKeyStore() = default;
		//! Import a header_and_message_keystore form a Protobuf-C struct.
		/*
		 * \param key_bundles An array of Protobuf-C key-bundles to import from.
		 */
		static result<HeaderAndMessageKeyStore> import(const span<ProtobufCKeyBundle*> key_bundles) noexcept;

		void add(const HeaderAndMessageKeyStore& keystore);
		void add(const EmptyableHeaderKey& header_key, const MessageKey& message_key);
		void add(const HeaderAndMessageKey& key);
		void remove(size_t index);
		void clear();

		void removeOutdatedAndTrimSize();

		const std::vector<HeaderAndMessageKey,SodiumAllocator<HeaderAndMessageKey>>& keys() const noexcept;

		//! Export a header_and_message_keystore as Protobuf-C struct.
		result<span<ProtobufCKeyBundle*>> exportProtobuf(Arena& arena) const;
	};

	std::ostream& operator<<(std::ostream& stream, const HeaderAndMessageKeyStore& keystore);
}
#endif
