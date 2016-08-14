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

#include "../lib/user-store.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

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
	buffer_destroy_from_heap_and_null(list);

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
	buffer_destroy_from_heap_and_null(list);
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
	buffer_destroy_from_heap_and_null(list);
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
	buffer_destroy_from_heap_and_null(list);
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
	buffer_destroy_from_heap_and_null(list);
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

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(200000, 0);
	mcJSON *json = user_store_json_export(store, pool);
	if (json == NULL) {
		buffer_destroy_from_heap_and_null(pool);
		throw(EXPORT_ERROR, "Failed to export to JSON.");
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	if (output == NULL) {
		buffer_destroy_from_heap_and_null(pool);
		throw(EXPORT_ERROR, "Failed to print exported JSON.");
	}
	printf("%.*s\n", (int) output->content_length, (char*)output->content);
	if (json->length != 2) {
		buffer_destroy_from_heap_and_null(output);
		buffer_destroy_from_heap_and_null(pool);
		throw(INCORRECT_DATA, "Exported JSON doesn't contain all users.");
	}
	buffer_destroy_from_heap_and_null(pool);

	//test JSON import
	user_store *imported_store;
	JSON_IMPORT(imported_store, 200000, output, user_store_json_import);
	if (imported_store == NULL) {
		buffer_destroy_from_heap_and_null(output);
		throw(IMPORT_ERROR, "Failed to import from JSON.");
	}

	//export the imported to JSON again
	JSON_EXPORT(imported_output, 200000, 4000, true, imported_store, user_store_json_export);
	user_store_destroy(imported_store);
	if (imported_output == NULL) {
		buffer_destroy_from_heap_and_null(output);
		throw(EXPORT_ERROR, "Failed to export the imported JSON again.");
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		buffer_destroy_from_heap_and_null(output);
		buffer_destroy_from_heap_and_null(imported_output);
		throw(INCORRECT_DATA, "Imported user store is incorrect.");
	}
	buffer_destroy_from_heap_and_null(output);
	buffer_destroy_from_heap_and_null(imported_output);

	//check the user list
	status = user_store_list(&list, store);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		throw(REMOVE_ERROR, "Removing user failed.");
	}
	buffer_destroy_from_heap_and_null(list);
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

cleanup:
	if (store != NULL) {
		user_store_destroy(store);
	}
	if (list != NULL) {
		buffer_destroy_from_heap_and_null(list);
	}

	buffer_destroy_from_heap_and_null(alice_public_signing_key);
	buffer_destroy_from_heap_and_null(bob_public_signing_key);
	buffer_destroy_from_heap_and_null(charlie_public_signing_key);

	if (status.status != SUCCESS) {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
