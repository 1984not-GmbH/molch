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

#include <user.pb-c.h>

#include "constants.h"
#include "common.h"
#include "../buffer/buffer.h"
#include "../mcJSON/mcJSON.h"

#ifndef LIB_MASTER_KEYS
#define LIB_MASTER_KEYS

typedef struct master_keys {
	//Ed25519 key for signing
	buffer_t public_signing_key[1];
	unsigned char public_signing_key_storage[PUBLIC_MASTER_KEY_SIZE];
	buffer_t private_signing_key[1];
	unsigned char private_signing_key_storage[PRIVATE_MASTER_KEY_SIZE];
	//X25519 key for deriving axolotl root keys
	buffer_t public_identity_key[1];
	unsigned char public_identity_key_storage[PUBLIC_KEY_SIZE];
	buffer_t private_identity_key[1];
	unsigned char private_identity_key_storage[PRIVATE_KEY_SIZE];
} master_keys;

/*
 * Create a new set of master keys.
 *
 * Seed is optional, can be NULL. It can be of any length and doesn't
 * require to have high entropy. It will be used as entropy source
 * in addition to the OSs CPRNG.
 *
 * WARNING: Don't use Entropy from the OSs CPRNG as seed!
 */
return_status master_keys_create(
		master_keys ** const keys, //output
		const buffer_t * const seed,
		buffer_t * const public_signing_key, //output, optional, can be NULL
		buffer_t * const public_identity_key //output, optional, can be NULL
		) __attribute__((warn_unused_result));

/*
 * Get the public signing key.
 */
return_status master_keys_get_signing_key(
		master_keys * const keys,
		buffer_t * const public_signing_key) __attribute__((warn_unused_result));

/*
 * Get the public identity key.
 */
return_status master_keys_get_identity_key(
		master_keys * const keys,
		buffer_t * const public_identity_key) __attribute__((warn_unused_result));

/*
 * Sign a piece of data. Returns the data and signature in one output buffer.
 */
return_status master_keys_sign(
		master_keys * const keys,
		const buffer_t * const data,
		buffer_t * const signed_data //output, length of data + SIGNATURE_SIZE
		) __attribute__((warn_unused_result));

/*! Export a set of master keys into a user Protobuf-C struct
 * \param master_keys A set of master keys to export.
 * \param public_signing_key Public pasrt of the signing keypair.
 * \param private_signing_key Private part of the signing keypair.
 * \param public_identity_key Public part of the identity keypair.
 * \param private_identity_key Private part of the idenity keypair.
 */
return_status master_keys_export(
		master_keys * const keys,
		Key ** const public_signing_key,
		Key ** const private_signing_key,
		Key ** const public_identity_key,
		Key ** const private_identity_key) __attribute__((warn_unused_result));

/*
 * Serialise the master keys into JSON. It get's a mempool_t buffer and stores mcJSON
 * Objects into it starting at pool->position.
 */
mcJSON *master_keys_json_export(master_keys * const keys, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialize a set of master keys (import from JSON).
 */
master_keys *master_keys_json_import(const mcJSON * const json) __attribute__((warn_unused_result));

#endif
