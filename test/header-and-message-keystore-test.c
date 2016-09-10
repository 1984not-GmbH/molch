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

#include "../lib/header-and-message-keystore.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"


int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//buffer for message keys
	buffer_t *header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	//initialise message keystore
	header_and_message_keystore keystore;
	header_and_message_keystore_init(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);

	int status_int = 0;
	//add keys to the keystore
	size_t i;
	for (i = 0; i < 6; i++) {
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

	//JSON export
	printf("Test JSON export!\n");
	JSON_EXPORT(output, 10000, 500, true, &keystore, header_and_message_keystore_json_export);
	if (output == NULL) {
		buffer_destroy_from_heap_and_null_if_valid(output);
		header_and_message_keystore_clear(&keystore);
		throw(EXPORT_ERROR, "Failed to export to JSON.");
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//JSON import
	header_and_message_keystore imported_keystore;
	JSON_INITIALIZE(&imported_keystore, 10000, output, header_and_message_keystore_json_import, status_int);
	if (status_int != 0) {
		buffer_destroy_from_heap_and_null_if_valid(output);
		throw(IMPORT_ERROR, "Failed to import keystore from JSON.");
	}
	//export the imported JSON to JSON again
	JSON_EXPORT(imported_output, 10000, 500, true, &imported_keystore, header_and_message_keystore_json_export);
	if (imported_output == NULL) {
		buffer_destroy_from_heap_and_null_if_valid(output);
		header_and_message_keystore_clear(&keystore);
		header_and_message_keystore_clear(&imported_keystore);
		throw(EXPORT_ERROR, "Failed to export from imported JSON.");
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		header_and_message_keystore_clear(&imported_keystore);
		buffer_destroy_from_heap_and_null_if_valid(output);
		buffer_destroy_from_heap_and_null_if_valid(imported_output);
		throw(INCORRECT_DATA, "Imported header and message keystore is incorrect.");
	}
	printf("Successfully imported header and message keystore from JSON.\n");
	buffer_destroy_from_heap_and_null_if_valid(imported_output);
	buffer_destroy_from_heap_and_null_if_valid(output);

	//remove key from the head
	printf("Remove head!\n");
	header_and_message_keystore_remove(&keystore, keystore.head);
	assert(keystore.length == (i - 1));
	print_header_and_message_keystore(&keystore);

	//remove key from the tail
	printf("Remove Tail:\n");
	header_and_message_keystore_remove(&keystore, keystore.tail);
	assert(keystore.length == (i - 2));
	print_header_and_message_keystore(&keystore);

	//remove from inside
	printf("Remove from inside:\n");
	header_and_message_keystore_remove(&keystore, keystore.head->next);
	assert(keystore.length == (i - 3));
	print_header_and_message_keystore(&keystore);

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(header_key);
	buffer_destroy_from_heap_and_null_if_valid(message_key);

	header_and_message_keystore_clear(&keystore);

	//clear the keystore
	printf("Clear the keystore:\n");
	header_and_message_keystore_clear(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);
	print_header_and_message_keystore(&keystore);

	on_error(
		print_errors(&status);
	)
	return_status_destroy_errors(&status);

	return status.status;
}
