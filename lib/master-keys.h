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

extern "C" {
	#include <user.pb-c.h>
}

#include "constants.h"
#include "common.h"
#include "buffer.h"

#ifndef LIB_MASTER_KEYS
#define LIB_MASTER_KEYS

class MasterKeys {
public:
	//Ed25519 key for signing
	Buffer public_signing_key;
	unsigned char public_signing_key_storage[PUBLIC_MASTER_KEY_SIZE];
	Buffer private_signing_key;
	unsigned char private_signing_key_storage[PRIVATE_MASTER_KEY_SIZE];
	//X25519 key for deriving axolotl root keys
	Buffer public_identity_key;
	unsigned char public_identity_key_storage[PUBLIC_KEY_SIZE];
	Buffer private_identity_key;
	unsigned char private_identity_key_storage[PRIVATE_KEY_SIZE];

	/*
	 * Create a new set of master keys.
	 *
	 * Seed is optional, can be nullptr. It can be of any length and doesn't
	 * require to have high entropy. It will be used as entropy source
	 * in addition to the OSs CPRNG.
	 *
	 * WARNING: Don't use Entropy from the OSs CPRNG as seed!
	 */
	static return_status create(
			MasterKeys*& keys, //output
			const Buffer * const seed, //optional
			Buffer * const public_signing_key, //output, optional, can be nullptr
			Buffer * const public_identity_key //output, optional, can be nullptr
			) noexcept __attribute__((warn_unused_result));

	/*
	 * Get the public signing key.
	 */
	return_status getSigningKey(Buffer& public_signing_key) noexcept __attribute__((warn_unused_result));

	/*
	 * Get the public identity key.
	 */
	return_status getIdentityKey(Buffer& public_identity_key) noexcept __attribute__((warn_unused_result));

	/*
	 * Sign a piece of data. Returns the data and signature in one output buffer.
	 */
	return_status sign(
			const Buffer& data,
			Buffer& signed_data //output, length of data + SIGNATURE_SIZE
			) noexcept __attribute__((warn_unused_result));

	/*! Export a set of master keys into a user Protobuf-C struct
	 * \param public_signing_key Public pasrt of the signing keypair.
	 * \param private_signing_key Private part of the signing keypair.
	 * \param public_identity_key Public part of the identity keypair.
	 * \param private_identity_key Private part of the idenity keypair.
	 */
	return_status exportMasterKeys(
			Key*& public_signing_key,
			Key*& private_signing_key,
			Key*& public_identity_key,
			Key*& private_identity_key) noexcept __attribute__((warn_unused_result));

	/*! Import a set of master keys from Protobuf-C structs
	 * \param keys A set of master keys to import to.
	 * \param public_signing_key Public part of the signing keypair (protobuf-c).
	 * \param private_signing_key Private part of the signing keypair (protobuf-c).
	 * \param public_identity_key Public part of the signing keypair (protobuf-c).
	 * \param private_identity_key Private part of the signing keypair (protobuf-c).
	 */
	static return_status import(
		MasterKeys*& keys,
		const Key * const public_signing_key,
		const Key * const private_signing_key,
		const Key * const public_identity_key,
		const Key * const private_identity_key) noexcept __attribute__((warn_unused_result));
};
#endif
