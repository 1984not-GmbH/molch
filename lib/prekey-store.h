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
public:
	PrekeyStoreNode *next;
	Buffer public_key;
	unsigned char public_key_storage[PUBLIC_KEY_SIZE];
	Buffer private_key;
	unsigned char private_key_storage[PRIVATE_KEY_SIZE];
	int64_t expiration_date;
};

class PrekeyStore {
public:
	int64_t oldest_expiration_date;
	PrekeyStoreNode prekeys[PREKEY_AMOUNT];
	PrekeyStoreNode *deprecated_prekeys;
	int64_t oldest_deprecated_expiration_date;
};

/*
 * Initialise a new keystore. Generates all the keys.
 */
return_status PrekeyStore_create(PrekeyStore ** const store) __attribute__((warn_unused_result));

/*
 * Get a private prekey from it's public key. This will automatically
 * deprecate the requested prekey put it in the outdated key store and
 * generate a new one.
 */
return_status PrekeyStore_get_prekey(
		PrekeyStore * const store,
		Buffer * const public_key, //input
		Buffer * const private_key) __attribute__((warn_unused_result)); //output

/*
 * Generate a list containing all public prekeys.
 * (this list can then be stored on a public server).
 */
return_status PrekeyStore_list(
		PrekeyStore * const store,
		Buffer * const list) __attribute__((warn_unused_result)); //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

/*
 * Automatically deprecate old keys and generate new ones
 * and THROW away deprecated ones that are too old.
 */
return_status PrekeyStore_rotate(PrekeyStore * const store) __attribute__((warn_unused_result));

void PrekeyStore_destroy(PrekeyStore * const store);

/*! Serialise a prekey store as protobuf-c struct.
 * \param PrekeyStore The prekey store to serialize.
 * \param keypairs An array of keypairs, allocated by the function.
 * \param keypairs_length The length of the array of keypairs.
 * \param deprecated_keypairs An array of deprecated keypairs, allocated by the function.
 * \param deprecated_keypairs_length The length of the array of deprecated keypairs.
 * \returns The status.
 */
return_status PrekeyStore_export(
		PrekeyStore * const store,
		Prekey *** const keypairs,
		size_t * const keypairs_length,
		Prekey *** const deprecated_keypairs,
		size_t * const deprecated_keypairs_length) __attribute__((warn_unused_result));

/*! Import a prekey store from a protobuf-c struct.
 * \param store The prekey store to import to.__a
 * \param keypairs An array of prekeys pairs.
 * \param keypais_length The length of the array of prekey pairs.
 * \param deprecated_keypairs An array of deprecated prekey pairs.
 * \param deprecated_keypairs_length The length of the array of deprecated prekey pairs.
 * \returns The status.
 */
return_status PrekeyStore_import(
		PrekeyStore ** const store,
		Prekey ** const keypairs,
		const size_t keypairs_length,
		Prekey ** const deprecated_keypairs,
		const size_t deprecated_keypairs_length) __attribute__((warn_unused_result));
#endif
