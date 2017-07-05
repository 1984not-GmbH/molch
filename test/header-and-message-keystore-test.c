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

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>
#include <string.h>

#include <key_bundle.pb-c.h>

#include "../lib/header-and-message-keystore.h"
#include "../lib/zeroed_malloc.h"
#include "utils.h"
#include "common.h"

static return_status protobuf_export(
			header_and_message_keystore * const keystore,
			KeyBundle *** const key_bundles,
			size_t * const bundles_size,
			buffer_t *** const export_buffers) {
	return_status status = return_status_init();

	status = header_and_message_keystore_export(
			keystore,
			key_bundles,
			bundles_size);
	throw_on_error(EXPORT_ERROR, "Failed to export keystore as protobuf struct.");

	*export_buffers = zeroed_malloc((*bundles_size) * sizeof(buffer_t*));
	throw_on_failed_alloc(*export_buffers);

	//initialize pointers with NULL
	memset(*export_buffers, '\0', (*bundles_size) * sizeof(buffer_t *));

	//create all the export buffers
	for (size_t i = 0; i < (*bundles_size); i++) {
		size_t export_size = key_bundle__get_packed_size((*key_bundles)[i]);
		(*export_buffers)[i] = buffer_create_on_heap(export_size, 0);
		throw_on_failed_alloc((*export_buffers)[i]);

		size_t packed_size = key_bundle__pack((*key_bundles)[i], (*export_buffers)[i]->content);
		(*export_buffers)[i]->content_length = packed_size;
	}

cleanup:
	// cleanup is done in the main function
	return status;
}

static return_status protobuf_import(
		header_and_message_keystore * const keystore,
		buffer_t ** const exported_buffers,
		size_t const buffers_size) {
	return_status status = return_status_init();

	KeyBundle ** key_bundles = zeroed_malloc(buffers_size * sizeof(KeyBundle*));
	throw_on_failed_alloc(key_bundles);

	//set all pointers to NULL
	memset(key_bundles, '\n', buffers_size * sizeof(KeyBundle*));

	//parse all the exported protobuf buffers
	for (size_t i = 0; i < buffers_size; i++) {
		key_bundles[i] = key_bundle__unpack(
			&protobuf_c_allocators,
			exported_buffers[i]->content_length,
			exported_buffers[i]->content);
		if (key_bundles[i] == NULL) {
			throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack key bundle from protobuf.");
		}
	}

	//now do the actual import
	status = header_and_message_keystore_import(
		keystore,
		key_bundles,
		buffers_size);
	throw_on_error(IMPORT_ERROR, "Failed to import header_and_message_keystore from Protobuf-C.");

cleanup:
	if (key_bundles != NULL) {
		for (size_t i = 0; i < buffers_size; i++) {
			if (key_bundles[i] != NULL) {
				key_bundle__free_unpacked(key_bundles[i], &protobuf_c_allocators);
				key_bundles[i] = NULL;
			}
		}
		zeroed_free_and_null_if_valid(key_bundles);
	}

	return status;
}

return_status protobuf_empty_store(void) __attribute__((warn_unused_result));
return_status protobuf_empty_store(void) {
	return_status status = return_status_init();

	printf("Testing im-/export of empty header and message keystore.\n");

	header_and_message_keystore store;
	header_and_message_keystore_init(&store);

	KeyBundle **exported = NULL;
	size_t exported_length = 0;

	//export it
	status = header_and_message_keystore_export(&store, &exported, &exported_length);
	throw_on_error(EXPORT_ERROR, "Failed to export empty header and message keystore.");

	if ((exported != NULL) || (exported_length != 0)) {
		throw(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	status = header_and_message_keystore_import(&store, exported, exported_length);
	throw_on_error(IMPORT_ERROR, "Failed to import empty header and message keystore.");

	printf("Successful.\n");

cleanup:
	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//buffer for message keys
	buffer_t *header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	// buffers for exporting protobuf-c
	buffer_t **protobuf_export_buffers = NULL;
	buffer_t **protobuf_second_export_buffers = NULL;
	KeyBundle ** protobuf_export_bundles = NULL;
	size_t protobuf_export_bundles_size = 0;
	KeyBundle ** protobuf_second_export_bundles = NULL;
	size_t protobuf_second_export_bundles_size = 0;

	//initialise message keystore
	header_and_message_keystore keystore;
	header_and_message_keystore_init(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);

	int status_int = 0;
	//add keys to the keystore
	for (size_t i = 0; i < 6; i++) {
		//create new keys
		status_int = buffer_fill_random(header_key, header_key->buffer_length);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to create header key.");
		}
		status_int = buffer_fill_random(message_key, message_key->buffer_length);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to create header key.");
		}

		//print the new header key
		printf("New Header Key No. %zu:\n", i);
		print_hex(header_key);
		putchar('\n');

		//print the new message key
		printf("New message key No. %zu:\n", i);
		print_hex(message_key);
		putchar('\n');

		//add keys to the keystore
		status = header_and_message_keystore_add(&keystore, message_key, header_key);
		buffer_clear(message_key);
		buffer_clear(header_key);
		throw_on_error(ADDITION_ERROR, "Failed to add key to keystore.");

		print_header_and_message_keystore(&keystore);

		assert(keystore.length == (i + 1));
	}

	//Protobuf-C export
	printf("Test Protobuf-C export:\n");
	status = protobuf_export(
			&keystore,
			&protobuf_export_bundles,
			&protobuf_export_bundles_size,
			&protobuf_export_buffers);
	throw_on_error(EXPORT_ERROR, "Failed to export keystore via protobuf-c.");

	puts("[\n");
	for (size_t i = 0; i < protobuf_export_bundles_size; i++) {
		print_hex(protobuf_export_buffers[i]);
		puts(",\n");
	}
	puts("]\n\n");

	printf("Import from Protobuf-C\n");
	header_and_message_keystore_clear(&keystore);
	protobuf_import(
		&keystore,
		protobuf_export_buffers,
		protobuf_export_bundles_size);
	throw_on_error(IMPORT_ERROR, "Failed to import from protobuf-c.");

	//now export again
	printf("Export imported as Protobuf-C\n");
	status = protobuf_export(
		&keystore,
		&protobuf_second_export_bundles,
		&protobuf_second_export_bundles_size,
		&protobuf_second_export_buffers);
	throw_on_error(EXPORT_ERROR, "Failed to export imported data via protobuf-c.");

	//compare both exports
	printf("Compare\n");
	if (protobuf_export_bundles_size != protobuf_second_export_bundles_size) {
		throw(INCORRECT_DATA, "Both exports contain different amounts of keys.");
	}
	size_t store_length;
	for (store_length = 0; store_length < protobuf_export_bundles_size; store_length++) {
		if (buffer_compare(protobuf_export_buffers[store_length], protobuf_second_export_buffers[store_length]) != 0) {
			throw(INCORRECT_DATA, "First and second export are not identical.");
		}
	}

	//remove key from the head
	printf("Remove head!\n");
	header_and_message_keystore_remove(&keystore, keystore.head);
	assert(keystore.length == (store_length - 1));
	print_header_and_message_keystore(&keystore);

	//remove key from the tail
	printf("Remove Tail:\n");
	header_and_message_keystore_remove(&keystore, keystore.tail);
	assert(keystore.length == (store_length - 2));
	print_header_and_message_keystore(&keystore);

	//remove from inside
	printf("Remove from inside:\n");
	header_and_message_keystore_remove(&keystore, keystore.head->next);
	assert(keystore.length == (store_length - 3));
	print_header_and_message_keystore(&keystore);

	status = protobuf_empty_store();
	throw_on_error(GENERIC_ERROR, "Testing im-/export of empty stores failed.");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(header_key);
	buffer_destroy_from_heap_and_null_if_valid(message_key);

	if (protobuf_export_bundles != NULL) {
		for (size_t i = 0; i < protobuf_export_bundles_size; i++) {
			if (protobuf_export_bundles[i] != NULL) {
				key_bundle__free_unpacked(protobuf_export_bundles[i], &protobuf_c_allocators);
				protobuf_export_bundles[i] = NULL;
			}
		}
		zeroed_free_and_null_if_valid(protobuf_export_bundles);
	}

	if (protobuf_export_buffers != NULL) {
		for (size_t i = 0; i < protobuf_export_bundles_size; i++) {
			if (protobuf_export_buffers[i] != NULL) {
				buffer_destroy_from_heap_and_null_if_valid(protobuf_export_buffers[i]);
			}
		}
		zeroed_free_and_null_if_valid(protobuf_export_buffers);
	}

	if (protobuf_second_export_bundles != NULL) {
		for (size_t i = 0; i < protobuf_second_export_bundles_size; i++) {
			if (protobuf_second_export_bundles[i] != NULL) {
				key_bundle__free_unpacked(protobuf_second_export_bundles[i], &protobuf_c_allocators);
				protobuf_second_export_bundles[i] = NULL;
			}
		}
		zeroed_free_and_null_if_valid(protobuf_second_export_bundles);
	}

	if (protobuf_second_export_buffers != NULL) {
		for (size_t i = 0; i < protobuf_export_bundles_size; i++) {
			if (protobuf_second_export_buffers[i] != NULL) {
				buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_buffers[i]);
			}
		}
		zeroed_free_and_null_if_valid(protobuf_second_export_buffers);
	}

	header_and_message_keystore_clear(&keystore);

	//clear the keystore
	printf("Clear the keystore:\n");
	header_and_message_keystore_clear(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);
	print_header_and_message_keystore(&keystore);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
