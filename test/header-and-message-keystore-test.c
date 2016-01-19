/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>

#include "../lib/header-and-message-keystore.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"


int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	//buffer for message keys
	buffer_t *header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *message_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	//initialise message keystore
	header_and_message_keystore keystore;
	header_and_message_keystore_init(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);

	int status;

	//add keys to the keystore
	unsigned int i;
	for (i = 0; i < 6; i++) {
		//create new keys
		status = buffer_fill_random(header_key, header_key->buffer_length);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to create header key. (%i)\n", status);
			goto cleanup;
		}
		status = buffer_fill_random(message_key, message_key->buffer_length);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to create header key. (%i)\n", status);
			goto cleanup;
		}

		//print the new header key
		printf("New Header Key No. %u:\n", i);
		print_hex(header_key);
		putchar('\n');

		//print the new message key
		printf("New message key No. %u:\n", i);
		print_hex(message_key);
		putchar('\n');

		//add keys to the keystore
		status = header_and_message_keystore_add(&keystore, message_key, header_key);
		buffer_clear(message_key);
		buffer_clear(header_key);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to add key to keystore. (%i)\n", status);
			goto cleanup;
		}

		print_header_and_message_keystore(&keystore);

		assert(keystore.length == (i + 1));
	}

	//JSON export
	printf("Test JSON export!\n");
	JSON_EXPORT(output, 10000, 500, true, &keystore, header_and_message_keystore_json_export);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to export to JSON.\n");
		buffer_destroy_from_heap(output);
		header_and_message_keystore_clear(&keystore);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//JSON import
	header_and_message_keystore imported_keystore;
	JSON_INITIALIZE(&imported_keystore, 10000, output, header_and_message_keystore_json_import, status);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to import keystore from JSON. (%i)\n", status);

		buffer_destroy_from_heap(output);
		goto cleanup;
	}
	//export the imported JSON to JSON again
	JSON_EXPORT(imported_output, 10000, 500, true, &imported_keystore, header_and_message_keystore_json_export);
	if (imported_output == NULL) {
		fprintf(stderr, "ERROR: Failed to import from exported JSON.\n");
		buffer_destroy_from_heap(output);
		header_and_message_keystore_clear(&keystore);
		header_and_message_keystore_clear(&imported_keystore);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported user store is incorrect.\n");
		header_and_message_keystore_clear(&imported_keystore);
		buffer_destroy_from_heap(output);
		buffer_destroy_from_heap(imported_output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully imported header and message keystore from JSON.\n");
	buffer_destroy_from_heap(imported_output);
	buffer_destroy_from_heap(output);

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
	buffer_destroy_from_heap(header_key);
	buffer_destroy_from_heap(message_key);

	header_and_message_keystore_clear(&keystore);

	//clear the keystore
	printf("Clear the keystore:\n");
	header_and_message_keystore_clear(&keystore);
	assert(keystore.length == 0);
	assert(keystore.head == NULL);
	assert(keystore.tail == NULL);
	print_header_and_message_keystore(&keystore);

	return status;
}
