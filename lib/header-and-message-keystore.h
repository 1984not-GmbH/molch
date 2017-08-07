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

#include <sodium.h>
#include <ctime>
#include <vector>
#include <string>

extern "C" {
	#include <key_bundle.pb-c.h>
}

#include "constants.h"
#include "buffer.h"
#include "return-status.h"
#include "sodium-wrappers.h"
#include "protobuf-deleters.h"

#ifndef LIB_HEADER_AND_MESSAGE_KEY_STORE_H
#define LIB_HEADER_AND_MESSAGE_KEY_STORE_H
//the message key store is currently a double linked list with all the message keys that haven't been
//used yet. (the keys are stored to still be able to decrypt old messages that weren't received)

//node of the linked list
class HeaderAndMessageKeyStoreNode {
private:
	void init();
	void fill(const Buffer& header_key, const Buffer& message_key, const int64_t expiration_date);

	unsigned char message_key_storage[MESSAGE_KEY_SIZE];
	unsigned char header_key_storage[HEADER_KEY_SIZE];

public:
	Buffer message_key;
	Buffer header_key;
	int64_t expiration_date;

	HeaderAndMessageKeyStoreNode();
	HeaderAndMessageKeyStoreNode(const Buffer& header_key, const Buffer& message_key);
	HeaderAndMessageKeyStoreNode(const Buffer& header_key, const Buffer& message_key, const int64_t expiration_date);
	/* copy constructor */
	HeaderAndMessageKeyStoreNode(const HeaderAndMessageKeyStoreNode& node);
	HeaderAndMessageKeyStoreNode(const KeyBundle& key_bundle);

	/* move assignment operator */
	HeaderAndMessageKeyStoreNode& operator=(HeaderAndMessageKeyStoreNode&& node);

	std::unique_ptr<KeyBundle,KeyBundleDeleter> exportProtobuf();

	std::string print() const;
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
	void exportProtobuf(KeyBundle**& key_bundles, size_t& bundles_size);

	std::string print() const;
};
#endif
