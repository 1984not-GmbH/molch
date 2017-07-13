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

extern "C" {
	#include <key_bundle.pb-c.h>
}

#include "constants.h"
#include "common.h"
#include "buffer.h"

#ifndef LIB_HEADER_AND_MESSAGE_KEY_STORE_H
#define LIB_HEADER_AND_MESSAGE_KEY_STORE_H
//the message key store is currently a double linked list with all the message keys that haven't been
//used yet. (the keys are stored to still be able to decrypt old messages that weren't received)

//node of the linked list
typedef struct header_and_message_keystore_node header_and_message_keystore_node;
struct header_and_message_keystore_node {
	header_and_message_keystore_node *previous;
	header_and_message_keystore_node *next;
	Buffer message_key[1];
	unsigned char message_key_storage[MESSAGE_KEY_SIZE];
	Buffer header_key[1];
	unsigned char header_key_storage[HEADER_KEY_SIZE];
	time_t expiration_date;
};

//header of the key store
typedef struct header_and_message_keystore {
	size_t length;
	header_and_message_keystore_node *head;
	header_and_message_keystore_node *tail;
} header_and_message_keystore;

//initialise a new keystore
void header_and_message_keystore_init(header_and_message_keystore * const keystore);

//add a hader and message key to the keystore
//NOTE: The entire keys are copied, not only the pointer
return_status header_and_message_keystore_add(
		header_and_message_keystore *keystore,
		const Buffer * const message_key,
		const Buffer * const header_key) __attribute__((warn_unused_result));

//remove a message key from the keystore
void header_and_message_keystore_remove(header_and_message_keystore *keystore, header_and_message_keystore_node *node);

//clear the entire keystore
void header_and_message_keystore_clear(header_and_message_keystore *keystore);

//! Export a header_and_message_keystore as Protobuf-C struct.
/*!
 * \param store The keystore to export.
 * \param key_bundles Pointer to a pointer of protobuf-c key bundle structs, it will be allocated in this function.
 * \param bundle_size Size of the outputted array.
 * \return The status.
 */
return_status header_and_message_keystore_export(
		const header_and_message_keystore * const store,
		KeyBundle *** const key_bundles,
		size_t * const bundles_size) __attribute__((warn_unused_result));

//! Import a header_and_message_keystore form a Protobuf-C struct.
/*
 * \param store The keystore to import to.
 * \param key_bundles An array of Protobuf-C key-bundles to import from.
 * \param bundles_size Size of the array.
 * \return The status.
 */
return_status header_and_message_keystore_import(
		header_and_message_keystore * const store,
		KeyBundle ** const key_bundles,
		const size_t bundles_size) __attribute__((warn_unused_result));
#endif
