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

extern "C" {
	#include <key_bundle.pb-c.h>
}

#include "constants.h"
#include "buffer.hpp"
#include "return-status.h"
#include "sodium-wrappers.hpp"
#include "protobuf-deleters.hpp"

class HeaderAndMessageKeyStoreNode {
private:
	void fill(const Buffer& header_key, const Buffer& message_key, const int64_t expiration_date);

	unsigned char message_key_storage[MESSAGE_KEY_SIZE];
	unsigned char header_key_storage[HEADER_KEY_SIZE];

	HeaderAndMessageKeyStoreNode& copy(const HeaderAndMessageKeyStoreNode& node);
	HeaderAndMessageKeyStoreNode& move(HeaderAndMessageKeyStoreNode&& node);

public:
	Buffer message_key{this->message_key_storage, sizeof(this->message_key_storage), 0};
	Buffer header_key{this->header_key_storage, sizeof(this->header_key_storage), 0};
	int64_t expiration_date{0};

	HeaderAndMessageKeyStoreNode() = default;
	HeaderAndMessageKeyStoreNode(const Buffer& header_key, const Buffer& message_key);
	HeaderAndMessageKeyStoreNode(const Buffer& header_key, const Buffer& message_key, const int64_t expiration_date);
	/* copy and move constructors */
	HeaderAndMessageKeyStoreNode(const HeaderAndMessageKeyStoreNode& node);
	HeaderAndMessageKeyStoreNode(HeaderAndMessageKeyStoreNode&& node);
	HeaderAndMessageKeyStoreNode(const KeyBundle& key_bundle);

	/* copy and move assignment operators */
	HeaderAndMessageKeyStoreNode& operator=(const HeaderAndMessageKeyStoreNode& node);
	HeaderAndMessageKeyStoreNode& operator=(HeaderAndMessageKeyStoreNode&& node);

	std::unique_ptr<KeyBundle,KeyBundleDeleter> exportProtobuf() const;

	std::ostream& print(std::ostream& stream) const;
};

//header of the key store
class HeaderAndMessageKeyStore {
public:
	std::vector<HeaderAndMessageKeyStoreNode,SodiumAllocator<HeaderAndMessageKeyStoreNode>> keys;

	HeaderAndMessageKeyStore() = default;
	//! Import a header_and_message_keystore form a Protobuf-C struct.
	/*
	 * \param key_bundles An array of Protobuf-C key-bundles to import from.
	 * \param bundles_size Size of the array.
	 */
	HeaderAndMessageKeyStore(KeyBundle** const & key_bundles, const size_t bundles_size);

	void add(const Buffer& header_key, const Buffer& message_key);
	//! Export a header_and_message_keystore as Protobuf-C struct.
	/*!
	 * \param key_bundles Pointer to a pointer of protobuf-c key bundle structs, it will be allocated in this function.
	 * \param bundle_size Size of the outputted array.
	 */
	void exportProtobuf(KeyBundle**& key_bundles, size_t& bundles_size) const;

	std::ostream& print(std::ostream& stream) const;
};
#endif
