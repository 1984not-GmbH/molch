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

#ifndef LIB_PrekeyStore
#define LIB_PrekeyStore

#include <ctime>
#include <memory>
#include <array>
#include <vector>
#include <ostream>
extern "C" {
	#include <prekey.pb-c.h>
}

#include "constants.h"
#include "buffer.hpp"
#include "return-status.h"
#include "zeroed_malloc.hpp"
#include "protobuf-deleters.hpp"
#include "sodium-wrappers.hpp"

class PrekeyStoreNode {
	friend class PrekeyStore;
private:
	unsigned char public_key_storage[PUBLIC_KEY_SIZE];
	unsigned char private_key_storage[PRIVATE_KEY_SIZE];

	void fill(const Buffer& public_key, const Buffer& private_key, const int64_t expiration_date);
	void generate();

	PrekeyStoreNode& copy(const PrekeyStoreNode& node);
	PrekeyStoreNode& move(PrekeyStoreNode&& node);

public:
	Buffer public_key{this->public_key_storage, sizeof(this->public_key_storage), 0};
	Buffer private_key{this->private_key_storage, sizeof(this->private_key_storage), 0};
	int64_t expiration_date{0};

	PrekeyStoreNode() = default;
	PrekeyStoreNode(const Buffer& public_key, const Buffer& private_key, int64_t expiration_date);
	/* copy constructor */
	PrekeyStoreNode(const PrekeyStoreNode& node);
	/* move constructor */
	PrekeyStoreNode(PrekeyStoreNode&& node);
	PrekeyStoreNode(const Prekey& keypair);

	/* copy assignment */
	PrekeyStoreNode& operator=(const PrekeyStoreNode& node);
	/* move assignment */
	PrekeyStoreNode& operator=(PrekeyStoreNode&& node);

	std::unique_ptr<Prekey,PrekeyDeleter> exportProtobuf() const;

	std::ostream& print(std::ostream& stream) const;
};

class PrekeyStore {
private:
	void init();
	void generateKeys();

	void updateExpirationDate();
	void updateDeprecatedExpirationDate();

	/*
	 * Helper that puts a prekey pair in the deprecated list and generates a new one.
	 */
	void deprecate(const size_t index);

public:
	int64_t oldest_expiration_date{0};
	int64_t oldest_deprecated_expiration_date{0};
	std::unique_ptr<std::array<PrekeyStoreNode,PREKEY_AMOUNT>,SodiumDeleter<std::array<PrekeyStoreNode,PREKEY_AMOUNT>>> prekeys;
	std::vector<PrekeyStoreNode,SodiumAllocator<PrekeyStoreNode>> deprecated_prekeys;
	//PrekeyStoreNode prekeys[PREKEY_AMOUNT];
	//PrekeyStoreNode *deprecated_prekeys;

	/*
	 * Initialise a new keystore. Generates all the keys.
	 */
	PrekeyStore();

	/*! Import a prekey store from a protobuf-c struct.
	 * \param keypairs An array of prekeys pairs.
	 * \param keypais_length The length of the array of prekey pairs.
	 * \param deprecated_keypairs An array of deprecated prekey pairs.
	 * \param deprecated_keypairs_length The length of the array of deprecated prekey pairs.
	 * \returns The status.
	 */
	PrekeyStore(
			Prekey** const& keypairs,
			const size_t keypairs_length,
			Prekey** const& deprecated_keypairs,
			const size_t deprecated_keypairs_length);

	/*
	 * Get a private prekey from it's public key. This will automatically
	 * deprecate the requested prekey put it in the outdated key store and
	 * generate a new one.
	 */
	void getPrekey(const Buffer& public_key, Buffer& private_key);

	/*
	 * Generate a list containing all public prekeys.
	 * (this list can then be stored on a public server).
	 */
	void list(Buffer& list) const; //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

	/*
	 * Automatically deprecate old keys and generate new ones
	 * and THROW away deprecated ones that are too old.
	 */
	void rotate();

	/*! Serialise a prekey store as protobuf-c struct.
	 * \param keypairs An array of keypairs, allocated by the function.
	 * \param keypairs_length The length of the array of keypairs.
	 * \param deprecated_keypairs An array of deprecated keypairs, allocated by the function.
	 * \param deprecated_keypairs_length The length of the array of deprecated keypairs.
	 */
	void exportProtobuf(
			Prekey**& keypairs,
			size_t& keypairs_length,
			Prekey**& deprecated_keypairs,
			size_t& deprecated_keypairs_length) const;

	std::ostream& print(std::ostream& stream) const;
};
#endif
