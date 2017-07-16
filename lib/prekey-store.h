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

#include <ctime>
extern "C" {
	#include <prekey.pb-c.h>
}

#include "constants.h"
#include "common.h"
#include "buffer.h"

#ifndef LIB_PrekeyStore
#define LIB_PrekeyStore

class PrekeyStoreNode {
	friend class PrekeyStore;
private:
	PrekeyStoreNode *next;
public:
	Buffer public_key;
	unsigned char public_key_storage[PUBLIC_KEY_SIZE];
	Buffer private_key;
	unsigned char private_key_storage[PRIVATE_KEY_SIZE];
	int64_t expiration_date;

	void init() noexcept;
	PrekeyStoreNode* getNext() noexcept;
	return_status exportNode(Prekey*& keypair) noexcept __attribute__((warn_unused_result));
	return_status import(const Prekey& keypair) noexcept __attribute__((warn_unused_result));
};

class PrekeyStore {
private:
	void addNodeToDeprecated(PrekeyStoreNode& deprecated_node) noexcept;
	int deprecate(const size_t index) noexcept;
	size_t countDeprecated() noexcept;
public:
	int64_t oldest_expiration_date;
	PrekeyStoreNode prekeys[PREKEY_AMOUNT];
	PrekeyStoreNode *deprecated_prekeys;
	int64_t oldest_deprecated_expiration_date;

	/*
	 * Initialise a new keystore. Generates all the keys.
	 */
	static return_status create(PrekeyStore*& store) noexcept __attribute__((warn_unused_result));

	/*
	 * Get a private prekey from it's public key. This will automatically
	 * deprecate the requested prekey put it in the outdated key store and
	 * generate a new one.
	 */
	return_status getPrekey(
			Buffer& public_key, //input
			Buffer& private_key) noexcept __attribute__((warn_unused_result)); //output

	/*
	 * Generate a list containing all public prekeys.
	 * (this list can then be stored on a public server).
	 */
	return_status list(Buffer& list) noexcept __attribute__((warn_unused_result)); //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

	/*
	 * Automatically deprecate old keys and generate new ones
	 * and THROW away deprecated ones that are too old.
	 */
	return_status rotate() noexcept __attribute__((warn_unused_result));

	void destroy() noexcept;

	/*! Serialise a prekey store as protobuf-c struct.
	 * \param keypairs An array of keypairs, allocated by the function.
	 * \param keypairs_length The length of the array of keypairs.
	 * \param deprecated_keypairs An array of deprecated keypairs, allocated by the function.
	 * \param deprecated_keypairs_length The length of the array of deprecated keypairs.
	 * \returns The status.
	 */
	return_status exportStore(
			Prekey**& keypairs,
			size_t& keypairs_length,
			Prekey**& deprecated_keypairs,
			size_t& deprecated_keypairs_length) noexcept __attribute__((warn_unused_result));

	/*! Import a prekey store from a protobuf-c struct.
	 * \param keypairs An array of prekeys pairs.
	 * \param keypais_length The length of the array of prekey pairs.
	 * \param deprecated_keypairs An array of deprecated prekey pairs.
	 * \param deprecated_keypairs_length The length of the array of deprecated prekey pairs.
	 * \returns The status.
	 */
	static return_status import(
			PrekeyStore*& store,
			Prekey** const keypairs,
			const size_t keypairs_length,
			Prekey** const deprecated_keypairs,
			const size_t deprecated_keypairs_length) noexcept __attribute__((warn_unused_result));
};
#endif
