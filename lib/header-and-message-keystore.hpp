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
#include <ctime>
#include <vector>
#include <ostream>

#include "constants.h"
#include "buffer.hpp"
#include "return-status.hpp"
#include "sodium-wrappers.hpp"
#include "protobuf.hpp"
#include "key.hpp"
#include "protobuf-pool.hpp"

namespace Molch {
	class HeaderAndMessageKey {
	private:
		void fill(const HeaderKey& header_key, const MessageKey& message_key, const int64_t expiration_date);

		HeaderAndMessageKey& copy(const HeaderAndMessageKey& node);
		HeaderAndMessageKey& move(HeaderAndMessageKey&& node);

	public:
		MessageKey message_key;
		HeaderKey header_key;
		int64_t expiration_date{0};

		HeaderAndMessageKey() = default;
		HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key);
		HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key, const int64_t expiration_date);
		/* copy and move constructors */
		HeaderAndMessageKey(const HeaderAndMessageKey& node);
		HeaderAndMessageKey(HeaderAndMessageKey&& node);
		HeaderAndMessageKey(const ProtobufCKeyBundle& key_bundle);

		/* copy and move assignment operators */
		HeaderAndMessageKey& operator=(const HeaderAndMessageKey& node);
		HeaderAndMessageKey& operator=(HeaderAndMessageKey&& node);

		ProtobufCKeyBundle* exportProtobuf(ProtobufPool& pool) const;

		std::ostream& print(std::ostream& stream) const;
	};

	//header of the key store
	class HeaderAndMessageKeyStore {
	public:
		std::vector<HeaderAndMessageKey,SodiumAllocator<HeaderAndMessageKey>> keys;

		HeaderAndMessageKeyStore() = default;
		//! Import a header_and_message_keystore form a Protobuf-C struct.
		/*
		 * \param key_bundles An array of Protobuf-C key-bundles to import from.
		 */
		HeaderAndMessageKeyStore(const span<ProtobufCKeyBundle*> key_bundles);

		void add(const HeaderKey& header_key, const MessageKey& message_key);
		//! Export a header_and_message_keystore as Protobuf-C struct.
		span<ProtobufCKeyBundle*> exportProtobuf(ProtobufPool& pool) const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif
