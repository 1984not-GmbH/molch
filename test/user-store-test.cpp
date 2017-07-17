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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <cassert>

#include "../lib/user-store.h"
#include "utils.h"
#include "common.h"

return_status protobuf_export(
		const user_store * const store,
		Buffer *** const export_buffers,
		size_t * const buffer_count) noexcept __attribute__((warn_unused_result));
return_status protobuf_export(
		const user_store * const store,
		Buffer *** const export_buffers,
		size_t * const buffer_count) noexcept {
	return_status status = return_status_init();

	User ** users = nullptr;
	size_t length = 0;

	if (export_buffers != nullptr) {
		*export_buffers = nullptr;
	}
	if (buffer_count != nullptr) {
		*buffer_count = 0;
	}

	//check input
	if ((store == nullptr) || (export_buffers == nullptr) || (buffer_count == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	status = user_store_export(store, &users, &length);
	THROW_on_error(EXPORT_ERROR, "Failed to export conversations.");

	*export_buffers = (Buffer**)malloc(length * sizeof(Buffer*));
	THROW_on_failed_alloc(*export_buffers);

	//initialize pointers with nullptr
	std::fill(*export_buffers, *export_buffers + length, nullptr);
	*buffer_count = length;

	//unpack all the conversations
	for (size_t i = 0; i < length; i++) {
		size_t unpacked_size = user__get_packed_size(users[i]);
		(*export_buffers)[i] = Buffer::create(unpacked_size, 0);
		THROW_on_failed_alloc((*export_buffers)[i]);

		(*export_buffers)[i]->content_length = user__pack(users[i], (*export_buffers)[i]->content);
	}

cleanup:
	if (users != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (users[i] != nullptr) {
				user__free_unpacked(users[i], &protobuf_c_allocators);
				users[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(users);
	}

	//buffer will be freed in main
	return status;
}

static return_status protobuf_import(
		user_store ** const store,
		Buffer ** const buffers,
		const size_t buffers_length) noexcept {
	return_status status = return_status_init();

	User **users = nullptr;

	//check input
	if ((store == nullptr) || (buffers == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	users = (User**)zeroed_malloc(buffers_length * sizeof(User*));
	THROW_on_failed_alloc(users);

	//unpack the buffers
	for (size_t i = 0; i < buffers_length; i++) {
		users[i] = user__unpack(&protobuf_c_allocators, buffers[i]->content_length, buffers[i]->content);
		if (users[i] == nullptr) {
			THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack user from protobuf.");
		}
	}

	//import the user store
	status = user_store_import(store, users, buffers_length);
	THROW_on_error(IMPORT_ERROR, "Failed to import users.");

cleanup:
	if (users != nullptr) {
		for (size_t i = 0; i < buffers_length; i++) {
			if (users[i] != nullptr) {
				user__free_unpacked(users[i], &protobuf_c_allocators);
			}
			users[i] = nullptr;
		}
		zeroed_free_and_null_if_valid(users);
	}
	return status;
}

return_status protobuf_empty_store(void) noexcept __attribute__((warn_unused_result));
return_status protobuf_empty_store(void) noexcept {
	return_status status = return_status_init();

	printf("Testing im-/export of empty user store.\n");

	User **exported = nullptr;
	size_t exported_length = 0;

	user_store *store = nullptr;
	status = user_store_create(&store);
	THROW_on_error(CREATION_ERROR, "Failed to create user store.");

	//export it
	status = user_store_export(store, &exported, &exported_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export empty user store.");

	if ((exported != nullptr) || (exported_length != 0)) {
		THROW(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	status = user_store_import(&store, exported, exported_length);
	THROW_on_error(IMPORT_ERROR, "Failed to import empty user store.");

	printf("Successful.\n");

cleanup:
	return status;
}

int main(void) noexcept {
	if (sodium_init() == -1) {
		return -1;
	}

	int status_int = 0;
	return_status status = return_status_init();

	//create public signing key buffers
	Buffer alice_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	Buffer bob_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	Buffer charlie_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);

	//protobuf-c export buffers
	Buffer **protobuf_export_buffers = nullptr;
	size_t protobuf_export_length = 0;
	Buffer **protobuf_second_export_buffers = nullptr;
	size_t protobuf_second_export_length = 0;

	Buffer *list = nullptr;

	//create a user_store
	user_store *store = nullptr;
	status = user_store_create(&store);
	THROW_on_error(CREATION_ERROR, "Failed to create user store.");

	throw_on_invalid_buffer(alice_public_signing_key);
	throw_on_invalid_buffer(bob_public_signing_key);
	throw_on_invalid_buffer(charlie_public_signing_key);

	//check the content
	status = user_store_list(&list, store);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list users in the user store.");
	if (list->content_length != 0) {
		THROW(INCORRECT_DATA, "List of users is not empty.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);

	//create alice
	status = user_store_create_user(
			store,
			nullptr,
			&alice_public_signing_key,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to create Alice.");
	printf("Successfully created Alice to the user store.\n");

	//check length of the user store
	if (store->length != 1) {
		THROW(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if (list == nullptr) {
		THROW(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
	}
	if (list->compare(&alice_public_signing_key) != 0) {
		THROW(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//create bob
	status = user_store_create_user(
			store,
			nullptr,
			&bob_public_signing_key,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to create Bob.");
	printf("Successfully created Bob.\n");

	//check length of the user store
	if (store->length != 2) {
		fprintf(stderr, "ERROR: User store has incorrect length.\n");
		THROW(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if (list == nullptr) {
		THROW(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
	}
	if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		THROW(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//create charlie
	status = user_store_create_user(
			store,
			nullptr,
			&charlie_public_signing_key,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to add Charlie to the user store.");
	printf("Successfully added Charlie to the user store.\n");

	//check length of the user store
	if (store->length != 3) {
		THROW(INCORRECT_DATA, "User store has incorrect length.");
	}
	printf("Length of the user store matches.");

	//list user store
	status = user_store_list(&list, store);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list users.")
	if (list == nullptr) {
		THROW(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
	}
	if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (list->comparePartial(2 * PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		THROW(INCORRECT_DATA, "Failed to list users.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully listed users.\n");

	//find node
	{
		user_store_node *bob_node = nullptr;
		status = user_store_find_node(&bob_node, store, &bob_public_signing_key);
		THROW_on_error(NOT_FOUND, "Failed to find Bob's node.");
		printf("Node found.\n");

		if (*bob_node->public_signing_key != bob_public_signing_key) {
			THROW(INCORRECT_DATA, "Bob's data from the user store doesn't match.");
		}
		printf("Data from the node matches.\n");

		//remove a user identified by it's key
		status = user_store_remove_by_key(store, &bob_public_signing_key);
		THROW_on_error(REMOVE_ERROR, "Failed to remvoe user from user store by key.");
		//check the length
		if (store->length != 2) {
			THROW(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Length of the user store matches.");
		//check the user list
		status = user_store_list(&list, store);
		THROW_on_error(DATA_FETCH_ERROR, "Failed to list users.");
		if (list == nullptr) {
			THROW(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
		}
		if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			THROW(INCORRECT_DATA, "Removing user failed.");
		}
		buffer_destroy_from_heap_and_null_if_valid(list);
		printf("Successfully removed user.\n");

		//recreate bob
		status = user_store_create_user(
				store,
				nullptr,
				&bob_public_signing_key,
				nullptr);
		THROW_on_error(CREATION_ERROR, "Failed to recreate.");
		printf("Successfully recreated Bob.\n");

		//now find bob again
		status = user_store_find_node(&bob_node, store, &bob_public_signing_key);
		THROW_on_error(NOT_FOUND, "Failed to find Bob's node.");
		printf("Bob's node found again.\n");

		//remove bob by it's node
		user_store_remove(store, bob_node);
		//check the length
		if (store->length != 2) {
			THROW(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Length of the user store matches.");
	}


	//test Protobuf-C export
	printf("Export to Protobuf-C\n");
	status = protobuf_export(store, &protobuf_export_buffers, &protobuf_export_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export user store to Protobuf-C.");

	//print the exported data
	puts("[\n");
	for (size_t i = 0; i < protobuf_export_length; i++) {
		print_hex(*protobuf_export_buffers[i]);
		puts(",\n");
	}
	puts("]\n\n");

	user_store_destroy(store);
	store = nullptr;

	//import from Protobuf-C
	printf("Import from Protobuf-C\n");
	status = protobuf_import(&store, protobuf_export_buffers, protobuf_export_length);
	THROW_on_error(IMPORT_ERROR, "Failed to import users from Protobuf-C.");

	if (store == nullptr) {
		THROW(SHOULDNT_HAPPEN, "Seems like this wasn't a false positive by clang static analyser!");
	}

	//export again
	printf("Export to Protobuf-C\n");
	status = protobuf_export(store, &protobuf_second_export_buffers, &protobuf_second_export_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export user store to Protobuf-C again.");

	//compare
	if (protobuf_export_length != protobuf_second_export_length) {
		THROW_on_error(INCORRECT_DATA, "Both exports have different sizes.");
	}
	for (size_t i = 0; i < protobuf_export_length; i++) {
		if (protobuf_export_buffers[i]->compare(protobuf_second_export_buffers[i]) != 0) {
			THROW_on_error(INCORRECT_DATA, "Buffers don't match.");
		}
	}
	printf("Both exports match.\n");

	//check the user list
	status = user_store_list(&list, store);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to list users.");
	if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
			|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
		THROW(REMOVE_ERROR, "Removing user failed.");
	}
	buffer_destroy_from_heap_and_null_if_valid(list);
	printf("Successfully removed user.\n");

	//clear the user store
	user_store_clear(store);
	//check the length
	if (store->length != 0) {
		THROW(INCORRECT_DATA, "User store has incorrect length.");
		goto cleanup;
	}
	//check head and tail pointers
	if ((store->head != nullptr) || (store->tail != nullptr)) {
		THROW(INCORRECT_DATA, "Clearing the user store didn't reset head and tail pointers.");
		status_int = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully cleared user store.\n");

	status = protobuf_empty_store();
	THROW_on_error(GENERIC_ERROR, "Failed im-/export with empty user store.");

cleanup:
	if (store != nullptr) {
		user_store_destroy(store);
	}
	buffer_destroy_from_heap_and_null_if_valid(list);

	if (protobuf_export_buffers != nullptr) {
		for (size_t i =0; i < protobuf_export_length; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_export_buffers);
	}
	if (protobuf_second_export_buffers != nullptr) {
		for (size_t i =0; i < protobuf_second_export_length; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_buffers[i]);
		}
		free_and_null_if_valid(protobuf_second_export_buffers);
	}

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
