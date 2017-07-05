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

#include "../lib/user-store.h"
#include "utils.h"
#include "common.h"

return_status protobuf_export(
		const user_store * const store,
		buffer_t *** const export_buffers,
		size_t * const buffer_count) __attribute__((warn_unused_result));
return_status protobuf_export(
		const user_store * const store,
		buffer_t *** const export_buffers,
		size_t * const buffer_count) {
	return_status status = return_status_init();

	User ** users = NULL;
	size_t length = 0;

	if (export_buffers != NULL) {
		*export_buffers = NULL;
	}
	if (buffer_count != NULL) {
		*buffer_count = 0;
	}

	//check input
	if ((store == NULL) || (export_buffers == NULL) || (buffer_count == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	status = user_store_export(store, &users, &length);
	throw_on_error(EXPORT_ERROR, "Failed to export conversations.");

	*export_buffers = malloc(length * sizeof(buffer_t*));
	throw_on_failed_alloc(*export_buffers);

	//initialize pointers with NULL
	memset(*export_buffers, '\0', length * sizeof(buffer_t*));
	*buffer_count = length;

	//unpack all the conversations
	for (size_t i = 0; i < length; i++) {
		size_t unpacked_size = user__get_packed_size(users[i]);
		(*export_buffers)[i] = buffer_create_on_heap(unpacked_size, 0);
		throw_on_failed_alloc((*export_buffers)[i]);

		(*export_buffers)[i]->content_length = user__pack(users[i], (*export_buffers)[i]->content);
	}

cleanup:
	if (users != NULL) {
		for (size_t i = 0; i < length; i++) {
			if (users[i] != NULL) {
				user__free_unpacked(users[i], &protobuf_c_allocators);
				users[i] = NULL;
			}
		}
		zeroed_free_and_null_if_valid(users);
	}

	//buffer will be freed in main
	return status;
}

static return_status protobuf_import(
		user_store ** const store,
		buffer_t ** const buffers,
		const size_t buffers_length) {
	return_status status = return_status_init();

	User **users = NULL;

	//check input
	if ((store == NULL) || (buffers == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	users = zeroed_malloc(buffers_length * sizeof(User*));
	throw_on_failed_alloc(users);

	//unpack the buffers
	for (size_t i = 0; i < buffers_length; i++) {
		users[i] = user__unpack(&protobuf_c_allocators, buffers[i]->content_length, buffers[i]->content);
		if (users[i] == NULL) {
			throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack user from protobuf.");
		}
	}

	//import the user store
	status = user_store_import(store, users, buffers_length);
	throw_on_error(IMPORT_ERROR, "Failed to import users.");

cleanup:
	if (users != NULL) {
		for (size_t i = 0; i < buffers_length; i++) {
			if (users[i] != NULL) {
				user__free_unpacked(users[i], &protobuf_c_allocators);
			}
			users[i] = NULL;
		}
		zeroed_free_and_null_if_valid(users);
	}
	return status;
}

return_status protobuf_empty_store(void) __attribute__((warn_unused_result));
return_status protobuf_empty_store(void) {
	return_status status = return_status_init();

	printf("Testing im-/export of empty user store.\n");

	User **exported = NULL;
	size_t exported_length = 0;

	user_store *store = NULL;
	status = user_store_create(&store);
	throw_on_error(CREATION_ERROR, "Failed to create user store.");

	//export it
	status = user_store_export(store, &exported, &exported_length);
	throw_on_error(EXPORT_ERROR, "Failed to export empty user store.");

	if ((exported != NULL) || (exported_length != 0)) {
		throw(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	status = user_store_import(&store, exported, exported_length);
	throw_on_error(IMPORT_ERROR, "Failed to import empty user store.");

	printf("Successful.\n");

cleanup:
	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status_int = 0;
	return_status status = return_status_init();

	//create public signing key buffers
	buffer_t *alice_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *bob_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *charlie_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);

	//protobuf-c export buffers
	buffer_t **protobuf_export_buffers = NULL;
	size_t protobuf_export_length = 0;
	buffer_t **protobuf_second_export_buffers = NULL;
	size_t protobuf_second_export_length = 0;

	buffer_t *list = NULL;

	//create a user_store
	user_store *store = NULL;
	status = user_store_create(&store);
	throw_on_error(CREATION_ERROR, "Failed to create user store.");

	//check the content
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users in the user store.");
	if (list->content_length != 0) {
		throw(INCORRECT_DATA, "List of users is not empty.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);

	//create alice
	status = user_store_create_user(
			store,
			NULL,
			alice_public_signing_key,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to create Alice.");
	printf("Successfully created Alice to the user store.\n");

	//check length of the user store
	if (store->length != 1) {
		throw(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if (list == NULL) {
		throw(INCORRECT_DATA, "Failed to list users, user list is NULL.");
	}
	if (buffer_compare(list, alice_public_signing_key) != 0) {
		throw(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//create bob
	status = user_store_create_user(
			store,
			NULL,
			bob_public_signing_key,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to create Bob.");
	printf("Successfully created Bob.\n");

	//check length of the user store
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		throw(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if (list == NULL) {
		throw(INCORRECT_DATA, "Failed to list users, user list is NULL.");
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		throw(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//create charlie
	status = user_store_create_user(
			store,
			NULL,
			charlie_public_signing_key,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to add Charlie to the user store.");
	printf("Successfully added Charlie to the user store.\n");

	//check length of the user store
	if (store->length != 3) {
		throw(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.")
	if (list == NULL) {
		throw(INCORRECT_DATA, "Failed to list users, user list is NULL.");
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, 2 * PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		throw(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//find node
	user_store_node *bob_node = NULL;
	status = user_store_find_node(&bob_node, store, bob_public_signing_key);
	throw_on_error(NOT_FOUND, "Failed to find Bob's node.");
	printf("Node found.\n");

	if (buffer_compare(bob_node->public_signing_key, bob_public_signing_key) != 0) {
		throw(INCORRECT_DATA, "Bob's data from the user store doesn't match.");
	}
	printf("Data from the node matches.\n");

	//remove a user identified by it's key
	status = user_store_remove_by_key(store, bob_public_signing_key);
	throw_on_error(REMOVE_ERROR, "Failed to remvoe user from user store by key.");
	//check the length
	if (store->length != 2) {
		throw(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");
	//check the user list
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if (list == NULL) {
		throw(INCORRECT_DATA, "Failed to list users, user list is NULL.");
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		throw(INCORRECT_DATA, "Removing user failed.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully removed user.\n");

	//recreate bob
	status = user_store_create_user(
			store,
			NULL,
			bob_public_signing_key,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to recreate.");
	printf("Successfully recreated Bob.\n");

	//now find bob again
	status = user_store_find_node(&bob_node, store, bob_public_signing_key);
	throw_on_error(NOT_FOUND, "Failed to find Bob's node.");
	printf("Bob's node found again.\n");

	//remove bob by it's node
	user_store_remove(store, bob_node);
	//check the length
	if (store->length != 2) {
		throw(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");


	//test Protobuf-C export
	printf("Export to Protobuf-C\n");
	status = protobuf_export(store, &protobuf_export_buffers, &protobuf_export_length);
	throw_on_error(EXPORT_ERROR, "Failed to export user store to Protobuf-C.");

	//print the exported data
	puts("[\n");
	for (size_t i = 0; i < protobuf_export_length; i++) {
		print_hex(protobuf_export_buffers[i]);
		puts(",\n");
	}
	puts("]\n\n");

	user_store_destroy(store);
	store = NULL;

	//import from Protobuf-C
	printf("Import from Protobuf-C\n");
	status = protobuf_import(&store, protobuf_export_buffers, protobuf_export_length);
	throw_on_error(IMPORT_ERROR, "Failed to import users from Protobuf-C.");

	if (store == NULL) {
		throw(SHOULDNT_HAPPEN, "Seems like this wasn't a false positive by clang static analyser!");
	}

	//export again
	printf("Export to Protobuf-C\n");
	status = protobuf_export(store, &protobuf_second_export_buffers, &protobuf_second_export_length);
	throw_on_error(EXPORT_ERROR, "Failed to export user store to Protobuf-C again.");

	//compare
	if (protobuf_export_length != protobuf_second_export_length) {
		throw_on_error(INCORRECT_DATA, "Both exports have different sizes.");
	}
	for (size_t i = 0; i < protobuf_export_length; i++) {
		if (buffer_compare(protobuf_export_buffers[i], protobuf_second_export_buffers[i]) != 0) {
			throw_on_error(INCORRECT_DATA, "Buffers don't match.");
		}
	}
	printf("Both exports match.\n");

	//check the user list
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		throw(REMOVE_ERROR, "Removing user failed.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully removed user.\n");

	//clear the user store
	user_store_clear(store);
	//check the length
	if (store->length != 0) {
		throw(INCORRECT_DATA, "User store has incorrect length.");
		goto cleanup;
	}
	//check head and tail pointers
	if ((store->head != NULL) || (store->tail != NULL)) {
		throw(INCORRECT_DATA, "Clearing the user store didn't reset head and tail pointers.");
		status_int = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully cleared user store.\n");

	status = protobuf_empty_store();
	throw_on_error(GENERIC_ERROR, "Failed im-/export with empty user store.");

cleanup:
	if (store != NULL) {
		user_store_destroy(store);
	}
	buffer_destroy_from_heap_and_null_if_valid(list);

	if (protobuf_export_buffers != NULL) {
		for (size_t i =0; i < protobuf_export_length; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_export_buffers);
	}
	if (protobuf_second_export_buffers != NULL) {
		for (size_t i =0; i < protobuf_second_export_length; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_second_export_buffers);
	}

	buffer_destroy_from_heap_and_null_if_valid(alice_public_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(charlie_public_signing_key);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
