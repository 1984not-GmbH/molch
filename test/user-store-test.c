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
#include "utils.h"
#include "common.h"

int generate_prekeys(buffer_t * const private_prekeys, buffer_t * const public_prekeys) {
	if ((private_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES))
			|| (public_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES))) {
		return -6;
	}

	private_prekeys->content_length = private_prekeys->buffer_length;
	public_prekeys->content_length = public_prekeys->buffer_length;

	int status;
	for (unsigned int i = 0; i < PREKEY_AMOUNT; i++) {
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
	//create three users with prekeys and identity keys
	//first alice
	//alice identity key
	buffer_t *alice_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			buffer_create_from_string("Alice"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's identity keypair.\n");
		buffer_clear(alice_private_identity);
		return status;
	}

	//alice prekeys
	buffer_t *alice_private_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	status = generate_prekeys(alice_private_prekeys, alice_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's prekeys.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		return status;
	}

	//then bob
	//bob's identity key
	buffer_t *bob_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			buffer_create_from_string("Bob"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's identity keypair.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		return status;
	}

	//bob's prekeys
	buffer_t *bob_private_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	status = generate_prekeys(bob_private_prekeys, bob_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's prekeys.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		return status;
	}

	//then charlie
	//charlie's identity key
	buffer_t *charlie_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			buffer_create_from_string("Charlie"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Charlie's identity keypair.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		return status;
	}

	//charlie's prekeys
	buffer_t *charlie_private_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	status = generate_prekeys(charlie_private_prekeys, charlie_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Charlie's prekeys.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		return status;
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
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return status;
	}
	printf("Successfully added Alice to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 1) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if (buffer_compare(list, alice_public_identity) != 0) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		buffer_destroy_from_heap(list);
		user_store_destroy(store);
		return EXIT_FAILURE;
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
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return status;
	}
	printf("Successfully added Bob to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, bob_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		buffer_destroy_from_heap(list);
		user_store_destroy(store);
		return EXIT_FAILURE;
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
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return status;
	}
	printf("Successfully added Charlie to the user store.\n");

	//check length of the user store
	sodium_mprotect_readonly(store);
	if (store->length != 3) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");

	//list user store
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, bob_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, 2 * crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Failed to list users.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		buffer_destroy_from_heap(list);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	buffer_destroy_from_heap(list);
	printf("Successfully listed users.\n");

	//find node
	user_store_node *bob_node = user_store_find_node(store, bob_public_identity);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	printf("Node found.\n");

	sodium_mprotect_readonly(bob_node);
	if ((buffer_compare(bob_node->public_identity_key, bob_public_identity) != 0)
			|| (buffer_compare(bob_node->private_identity_key, bob_private_identity) != 0)
			|| (buffer_compare_to_raw(bob_public_prekeys, bob_node->public_prekey_storage, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_to_raw(bob_private_prekeys, bob_node->private_prekey_storage, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Bob's data from the user store doesn't match.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(bob_node);
	printf("Data from the node matches.\n");

	//remove a user identified by it's key
	user_store_remove_by_key(store, bob_public_identity);
	//check the length
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");
	//check the user list
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		buffer_destroy_from_heap(list);
		return EXIT_FAILURE;
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
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return status;
	}
	printf("Successfully readded Bob to the user store.\n");

	//now find bob again
	bob_node = user_store_find_node(store, bob_public_identity);
	if (bob_node == NULL) {
		fprintf(stderr, "ERROR: Failed to find Bob's node.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	printf("Bob's node found again.\n");

	//remove bob by it's node
	user_store_remove(store, bob_node);
	//check the length
	sodium_mprotect_readonly(store);
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	sodium_mprotect_noaccess(store);
	printf("Length of the user store matches.");
	//check the user list
	list = user_store_list(store);
	if ((buffer_compare_partial(list, 0, alice_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)
			|| (buffer_compare_partial(list, crypto_box_PUBLICKEYBYTES, charlie_public_identity, 0, crypto_box_PUBLICKEYBYTES) != 0)) {
		fprintf(stderr, "ERROR: Removing user failed.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_prekeys);
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_prekeys);
		user_store_destroy(store);
		buffer_destroy_from_heap(list);
		return EXIT_FAILURE;
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
		user_store_destroy(store);
		return EXIT_FAILURE;
	}
	printf("Successfully cleared user store.\n");

	sodium_mprotect_noaccess(store);

	user_store_destroy(store);
	return EXIT_SUCCESS;
}
