/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include "../lib/user-store.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status = 0;

	//create public signing key buffers
	buffer_t *alice_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *bob_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *charlie_public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);

	buffer_t *list = NULL;

	//create a user_store
	user_store *store = user_store_create();
	if (store == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//check the content
	list = user_store_list(store);
	if (list == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if (list->content_length != 0) {
		fprintf(stderr, "ERROR: List of users is not empty.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;

	//create alice
	status = user_store_create_user(
			store,
			NULL,
			alice_public_signing_key,
			NULL);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create Alice.\n");
		goto cleanup;
	}
	printf("Successfully created Alice to the user store.\n");

	//check length of the user store
	if (store->length != 1) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if (list == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if (buffer_compare(list, alice_public_signing_key) != 0) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;
	printf("Successfully listed users.\n");

	//create bob
	status = user_store_create_user(
			store,
			NULL,
			bob_public_signing_key,
			NULL);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create Bob.\n");
		goto cleanup;
	}
	printf("Successfully created Bob.\n");

	//check length of the user store
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if (list == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;
	printf("Successfully listed users.\n");

	//create charlie
	status = user_store_create_user(
			store,
			NULL,
			charlie_public_signing_key,
			NULL);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add Charlie to the user store.\n");
		goto cleanup;
	}
	printf("Successfully added Charlie to the user store.\n");

	//check length of the user store
	if (store->length != 3) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if (list == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, 2 * PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;
	printf("Successfully listed users.\n");

	//find node
	user_store_node *bob_node = user_store_find_node(store, bob_public_signing_key);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Node found.\n");

	if (buffer_compare(bob_node->public_signing_key, bob_public_signing_key) != 0) {
		fprintf(stderr, "ERROR: Bob's data from the user store doesn't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Data from the node matches.\n");

	//remove a user identified by it's key
	user_store_remove_by_key(store, bob_public_signing_key);
	//check the length
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Length of the user store matches.");
	//check the user list
	list = user_store_list(store);
	if (list == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;
	printf("Successfully removed user.\n");

	//recreate bob
	status = user_store_create_user(
			store,
			NULL,
			bob_public_signing_key,
			NULL);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to recreate.\n");
		goto cleanup;
	}
	printf("Successfully recreated Bob.\n");

	//now find bob again
	bob_node = user_store_find_node(store, bob_public_signing_key);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Bob's node found again.\n");

	//remove bob by it's node
	user_store_remove(store, bob_node);
	//check the length
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Length of the user store matches.");

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(200000, 0);
	mcJSON *json = user_store_json_export(store, pool);
	if (json == NULL) {
		fprintf(stderr, "ERROR: Failed to export to JSON!\n");
		buffer_destroy_from_heap(pool);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to print exported JSON.\n");
		buffer_destroy_from_heap(pool);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("%.*s\n", (int) output->content_length, (char*)output->content);
	if (json->length != 2) {
		fprintf(stderr, "ERROR: Exported JSON doesn't contain all users.\n");
		buffer_destroy_from_heap(output);
		buffer_destroy_from_heap(pool);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(pool);

	//test JSON import
	user_store *imported_store;
	JSON_IMPORT(imported_store, 200000, output, user_store_json_import);
	if (imported_store == NULL) {
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//export the imported to JSON again
	JSON_EXPORT(imported_output, 200000, 4000, true, imported_store, user_store_json_export);
	user_store_destroy(imported_store);
	if (imported_output == NULL) {
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported user store is incorrect.\n");
		status = EXIT_FAILURE;
		buffer_destroy_from_heap(output);
		buffer_destroy_from_heap(imported_output);
		goto cleanup;
	}
	buffer_destroy_from_heap(output);
	buffer_destroy_from_heap(imported_output);

	//check the user list
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (buffer_compare_partial(list, PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	list = NULL;
	printf("Successfully removed user.\n");

	//clear the user store
	user_store_clear(store);
	//check the length
	if (store->length != 0) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	//check head and tail pointers
	if ((store->head != NULL) || (store->tail != NULL)) {
		fprintf(stderr, "ERROR: Clearing the user store didn't reset head and tail pointers.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully cleared user store.\n");


cleanup:
	if (store != NULL) {
		user_store_destroy(store);
	}
	if (list != NULL) {
		buffer_destroy_from_heap(list);
	}

	buffer_destroy_from_heap(alice_public_signing_key);
	buffer_destroy_from_heap(bob_public_signing_key);
	buffer_destroy_from_heap(charlie_public_signing_key);

	return status;
}
