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

#include "../lib/user-store.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

int generate_prekeys(buffer_t * const private_prekeys, buffer_t * const public_prekeys) {
	if ((private_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES))
			|| (public_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES))) {
		return -6;
	}

	private_prekeys->content_length = private_prekeys->buffer_length;
	public_prekeys->content_length = public_prekeys->buffer_length;

	int status;
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = crypto_box_keypair(
				public_prekeys->content + i * crypto_box_PUBLICKEYBYTES,
				private_prekeys->content + i * crypto_box_SECRETKEYBYTES);
		if (status != 0) {
			buffer_clear(public_prekeys);
			buffer_clear(private_prekeys);
			return status;
		}
	}
	return 0;
}


int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	//create a user_store
	user_store *store = user_store_create();

	//check the content
	buffer_t *list = user_store_list(store);
	if (list->content_length != 0) {
		fprintf(stderr, "ERROR: List of users is not empty.\n");
		user_store_destroy(store);
		buffer_destroy_from_heap(list);

		return EXIT_FAILURE;
	}
	buffer_destroy_from_heap(list);

	int status;
	//create buffers
	//alice keys
	buffer_t *alice_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	//bobs keys
	buffer_t *bob_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	//charlies keys
	buffer_t *charlie_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *charlie_private_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_prekeys = buffer_create_on_heap(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);

	//create three users with prekeys and identity keys
	//first alice
	//alice identity key
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's identity keypair.\n");
		goto cleanup;
	}

	//alice prekeys
	status = generate_prekeys(alice_private_prekeys, alice_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's prekeys.\n");
		goto cleanup;
	}

	//then bob
	//bob's identity key
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			bob_string,
			identity_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's identity keypair.\n");
		goto cleanup;
	}

	//bob's prekeys
	status = generate_prekeys(bob_private_prekeys, bob_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's prekeys.\n");
		goto cleanup;
	}

	//then charlie
	//charlie's identity key
	buffer_create_from_string(charlie_string, "Charlie");
	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			charlie_string,
			identity_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Charlie's identity keypair.\n");
		goto cleanup;
	}

	//charlie's prekeys
	status = generate_prekeys(charlie_private_prekeys, charlie_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Charlie's prekeys.\n");
		goto cleanup;
	}

	//add alice to the user store
	status = user_store_add(
			store,
			alice_public_identity,
			alice_private_identity,
			alice_public_prekeys,
			alice_private_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add Alice to the user store.\n");
		goto cleanup;
	}
	printf("Successfully added Alice to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 1) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if (buffer_compare(list, alice_public_identity) != 0) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_destroy_from_heap(list);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully listed users.\n");

	//add bob to the user store
	status = user_store_add(
			store,
			bob_public_identity,
			bob_private_identity,
			bob_public_prekeys,
			bob_private_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add Bob to the user store.\n");
		goto cleanup;
	}
	printf("Successfully added Bob to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, bob_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_destroy_from_heap(list);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully listed users.\n");

	//add charlie to the user store
	status = user_store_add(
			store,
			charlie_public_identity,
			charlie_private_identity,
			charlie_public_prekeys,
			charlie_private_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add Charlie to the user store.\n");
		goto cleanup;
	}
	printf("Successfully added Charlie to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 3) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, bob_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, 2 * crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_destroy_from_heap(list);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully listed users.\n");

	//check alice's prekeys
	sodium_mprotect_readonly(store);
	sodium_mprotect_readonly(store->head);
	//check the storage
	//private
	if (sodium_memcmp(store->head->private_prekey_storage, alice_private_prekeys->content, alice_private_prekeys->content_length) != 0) {
		fprintf(stderr, "ERROR: Alice's private prekeys are incorrect.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	//public
	if (sodium_memcmp(store->head->public_prekey_storage, alice_public_prekeys->content, alice_public_prekeys->content_length) != 0) {
		fprintf(stderr, "ERROR: Alice's public prekeys are incorrect.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//check the buffers
	//private
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = buffer_compare_to_raw(&store->head->private_prekeys[i], alice_private_prekeys->content + i * crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);
		if (status != 0) {
			fprintf(stderr, "ERROR: Alice's private prekeys are incorrect (buffer_t).\n");
			goto cleanup;
		}
	}
	//public
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = buffer_compare_to_raw(&store->head->public_prekeys[i], alice_public_prekeys->content + i * crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		if (status != 0) {
			fprintf(stderr, "ERROR: Alice's public prekeys are incorrect (buffer_t).\n");
			goto cleanup;
		}
	}
	sodium_mprotect_noaccess(store->head);
	sodium_mprotect_noaccess(store);
	printf("Alice's Prekeys have been correctly store!\n");

	//find node
	user_store_node *bob_node = user_store_find_node(store, bob_public_identity);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Node found.\n");

	sodium_mprotect_readonly(bob_node);
	if ((buffer_compare(bob_node->public_identity_key, bob_public_identity) != 0)
			|| (buffer_compare(bob_node->private_identity_key, bob_private_identity) != 0)
			|| (buffer_compare_to_raw(bob_public_prekeys, bob_node->public_prekey_storage, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_to_raw(bob_private_prekeys, bob_node->private_prekey_storage, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Bob's data from the user store doesn't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(bob_node);
	printf("Data from the node matches.\n");

	//remove a user identified by it's key
	user_store_remove_by_key(store, bob_public_identity);
	//check the length
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");
	//check the user list
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		buffer_destroy_from_heap(list);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully removed user.\n");

	//readd bob
	status = user_store_add(
			store,
			bob_public_identity,
			bob_private_identity,
			bob_public_prekeys,
			bob_private_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to readd Bob to the user store.\n");
		goto cleanup;
	}
	printf("Successfully readded Bob to the user store.\n");

	//now find bob again
	bob_node = user_store_find_node(store, bob_public_identity);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Bob's node found again.\n");

	//remove bob by it's node
	user_store_remove(store, bob_node);
	//check the length
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(100000, 0);
	mcJSON *json = user_store_json_export(store, pool);
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
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
	JSON_IMPORT(imported_store, 100000, output, user_store_json_import);
	if (imported_store == NULL) {
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//export the imported to JSON again
	JSON_EXPORT(imported_output, 100000, 4000, true, imported_store, user_store_json_export);
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
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		buffer_destroy_from_heap(list);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully removed user.\n");

	buffer_clear(alice_private_identity);
	buffer_clear(alice_private_prekeys);
	buffer_clear(bob_private_identity);
	buffer_clear(bob_private_prekeys);
	buffer_clear(charlie_private_identity);
	buffer_clear(charlie_private_prekeys);

	//clear the user store
	user_store_clear(store);
	//check the length
	sodium_mprotect_readonly(store);
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

	sodium_mprotect_noaccess(store);

cleanup:
	//alice keys
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_prekeys);
	buffer_destroy_from_heap(alice_public_prekeys);
	//bobs keys
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_prekeys);
	buffer_destroy_from_heap(bob_public_prekeys);
	//charlies keys
	buffer_destroy_from_heap(charlie_private_identity);
	buffer_destroy_from_heap(charlie_public_identity);
	buffer_destroy_from_heap(charlie_private_prekeys);
	buffer_destroy_from_heap(charlie_public_prekeys);

	user_store_destroy(store);

	return status;
}
