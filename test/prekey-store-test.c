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
#include <string.h>

#include "../lib/prekey-store.h"
#include "../lib/constants.h"
#include "utils.h"

static return_status protobuf_export(
		prekey_store * const store,
		Prekey *** const keypairs,
		size_t * const keypairs_size,
		buffer_t *** const key_buffers,
		Prekey *** const deprecated_keypairs,
		size_t * const deprecated_keypairs_size,
		buffer_t *** const deprecated_key_buffers) {
	return_status status = return_status_init();

	status = prekey_store_export(
		store,
		keypairs,
		keypairs_size,
		deprecated_keypairs,
		deprecated_keypairs_size);
	throw_on_error(EXPORT_ERROR, "Failed to export prekeys.");

	*key_buffers = zeroed_malloc((*keypairs_size) * sizeof(buffer_t*));
	throw_on_failed_alloc(*key_buffers);

	//initialize pointers with NULL
	memset(*key_buffers, '\0', (*keypairs_size) * sizeof(buffer_t*));

	*deprecated_key_buffers = zeroed_malloc((*deprecated_keypairs_size) * sizeof(buffer_t*));
	throw_on_failed_alloc(*deprecated_key_buffers);

	//initialize pointers with NULL
	memset(*deprecated_key_buffers, '\0', (*deprecated_keypairs_size) * sizeof(buffer_t*));

	//export all the keypairs
	for (size_t i = 0; i < (*keypairs_size); i++) {
		size_t export_size = prekey__get_packed_size((*keypairs)[i]);
		(*key_buffers)[i] = buffer_create_on_heap(export_size, 0);
		throw_on_failed_alloc((*key_buffers)[i]);

		size_t packed_size = prekey__pack((*keypairs)[i], (*key_buffers)[i]->content);
		(*key_buffers)[i]->content_length = packed_size;
	}

	//export all the deprecated keypairs
	for (size_t i = 0; i < (*deprecated_keypairs_size); i++) {
		size_t export_size = prekey__get_packed_size((*deprecated_keypairs)[i]);
		(*deprecated_key_buffers)[i] = buffer_create_on_heap(export_size, 0);
		throw_on_failed_alloc((*deprecated_key_buffers)[i]);

		size_t packed_size = prekey__pack((*deprecated_keypairs)[i], (*deprecated_key_buffers)[i]->content);
		(*deprecated_key_buffers)[i]->content_length = packed_size;
	}
cleanup:
	//cleanup is done in the main function

	return status;
}

static return_status protobuf_import(
		prekey_store ** const store,
		buffer_t ** const keypair_buffers,
		const size_t keypair_buffers_size,
		buffer_t ** const deprecated_keypair_buffers,
		const size_t deprecated_keypair_buffers_size) {
	return_status status = return_status_init();

	Prekey ** keypairs = NULL;
	Prekey ** deprecated_keypairs = NULL;

	keypairs = zeroed_malloc(keypair_buffers_size * sizeof(Prekey*));
	throw_on_failed_alloc(keypairs);
	memset(keypairs, '\0', keypair_buffers_size * sizeof(Prekey*));

	deprecated_keypairs = zeroed_malloc(deprecated_keypair_buffers_size * sizeof(Prekey*));
	memset(deprecated_keypairs, '\0', deprecated_keypair_buffers_size * sizeof(Prekey*));
	throw_on_failed_alloc(deprecated_keypairs);

	//parse the normal prekey protobufs
	for (size_t i = 0; i < keypair_buffers_size; i++) {
		keypairs[i] = prekey__unpack(
			&protobuf_c_allocators,
			keypair_buffers[i]->content_length,
			keypair_buffers[i]->content);
		if (keypairs[i] == NULL) {
			throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack prekey from protobuf.");
		}
	}

	//parse the deprecated prekey protobufs
	for (size_t i = 0; i < deprecated_keypair_buffers_size; i++) {
		deprecated_keypairs[i] = prekey__unpack(
			&protobuf_c_allocators,
			deprecated_keypair_buffers[i]->content_length,
			deprecated_keypair_buffers[i]->content);
		if (deprecated_keypairs[i] == NULL) {
			throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack deprecated prekey from protobuf.");
		}
	}

	//now do the import
	status = prekey_store_import(
		store,
		keypairs,
		keypair_buffers_size,
		deprecated_keypairs,
		deprecated_keypair_buffers_size);
	throw_on_error(IMPORT_ERROR, "Failed to import prekeys.");

cleanup:
	if (keypairs != NULL) {
		for (size_t i = 0; i < keypair_buffers_size; i++) {
			prekey__free_unpacked(keypairs[i], &protobuf_c_allocators);
			keypairs[i] = NULL;
		}

		zeroed_free_and_null_if_valid(keypairs);
	}

	if (deprecated_keypairs != NULL) {
		for (size_t i = 0; i < deprecated_keypair_buffers_size; i++) {
			prekey__free_unpacked(deprecated_keypairs[i], &protobuf_c_allocators);
			deprecated_keypairs[i] = NULL;
		}

		zeroed_free_and_null_if_valid(deprecated_keypairs);
	}

	return status;
}

return_status protobuf_no_deprecated_keys(void) __attribute__((warn_unused_result));
return_status protobuf_no_deprecated_keys(void) {
	return_status status = return_status_init();

	printf("Testing im-/export of prekey store without deprecated keys.\n");

	prekey_store *store = NULL;

	Prekey **exported = NULL;
	size_t exported_length = 0;
	Prekey **deprecated = NULL;
	size_t deprecated_length = 0;

	status = prekey_store_create(&store);
	throw_on_error(CREATION_ERROR, "Failed to create prekey store.");

	//export it
	status = prekey_store_export(
		store,
		&exported,
		&exported_length,
		&deprecated,
		&deprecated_length);
	throw_on_error(EXPORT_ERROR, "Failed to export prekey store without deprecated keys.");

	if ((deprecated != NULL) || (deprecated_length != 0)) {
		throw(INCORRECT_DATA, "Exported deprecated prekeys are not empty.");
	}

	//import it
	status = prekey_store_import(
		&store,
		exported,
		exported_length,
		deprecated,
		deprecated_length);
	throw_on_error(IMPORT_ERROR, "Failed to import prekey store without deprecated prekeys.");

	printf("Successful.\n");

cleanup:
	if (exported != NULL) {
		for (size_t i = 0; i < exported_length; i++) {
			prekey__free_unpacked(exported[i], &protobuf_c_allocators);
			exported[i] = 0;
		}
		zeroed_free_and_null_if_valid(exported);
	}

	if (store != NULL) {
		prekey_store_destroy(store);
	}

	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	buffer_t *public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *private_prekey1 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *private_prekey2 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *prekey_list = buffer_create_on_heap(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);

	Prekey **protobuf_export_prekeys = NULL;
	buffer_t **protobuf_export_prekeys_buffers = NULL;
	size_t protobuf_export_prekeys_size = 0;
	Prekey **protobuf_export_deprecated_prekeys = NULL;
	buffer_t **protobuf_export_deprecated_prekeys_buffers = NULL;
	size_t protobuf_export_deprecated_prekeys_size = 0;

	Prekey **protobuf_second_export_prekeys = NULL;
	buffer_t **protobuf_second_export_prekeys_buffers = NULL;
	size_t protobuf_second_export_prekeys_size = 0;
	Prekey **protobuf_second_export_deprecated_prekeys = NULL;
	buffer_t **protobuf_second_export_deprecated_prekeys_buffers = NULL;
	size_t protobuf_second_export_deprecated_prekeys_size = 0;

	prekey_store *store = NULL;
	status = prekey_store_create(&store);
	throw_on_error(CREATION_ERROR, "Failed to create a prekey store.");

	status = prekey_store_list(store, prekey_list);
	throw_on_error(DATA_FETCH_ERROR, "Failed to list prekeys.");
	printf("Prekey list:\n");
	print_hex(prekey_list);
	putchar('\n');

	//compare the public keys with the ones in the prekey store
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare_partial(prekey_list, PUBLIC_KEY_SIZE * i, store->prekeys[i].public_key, 0, PUBLIC_KEY_SIZE) != 0) {
			throw(INCORRECT_DATA, "Key list doesn't match the prekey store.");
		}
	}
	printf("Prekey list matches the prekey store!\n");

	//get a private key
	const size_t prekey_index = 10;
	if (buffer_clone(public_prekey, store->prekeys[prekey_index].public_key) != 0) {
		throw(BUFFER_ERROR, "Failed to clone public key.");
	}

	status = prekey_store_get_prekey(store, public_prekey, private_prekey1);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get prekey.")
	printf("Get a Prekey:\n");
	printf("Public key:\n");
	print_hex(public_prekey);
	printf("Private key:\n");
	print_hex(private_prekey1);
	putchar('\n');

	if (store->deprecated_prekeys == NULL) {
		throw(GENERIC_ERROR, "Failed to deprecate requested key.");
	}

	if ((buffer_compare(public_prekey, store->deprecated_prekeys->public_key) != 0)
			|| (buffer_compare(private_prekey1, store->deprecated_prekeys->private_key) != 0)) {
		throw(INCORRECT_DATA, "Deprecated key is incorrect.");
	}

	if (buffer_compare(store->prekeys[prekey_index].public_key, public_prekey) == 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate new key for deprecated one.");
	}
	printf("Successfully deprecated requested key!\n");

	//check if the prekey can be obtained from the deprecated keys
	status = prekey_store_get_prekey(store, public_prekey, private_prekey2);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get key from the deprecated area.");

	if (buffer_compare(private_prekey1, private_prekey2) != 0) {
		throw(INCORRECT_DATA, "Prekey from the deprecated area didn't match.");
	}
	printf("Successfully got prekey from the deprecated area!\n");

	//try to get a nonexistent key
	if (buffer_fill_random(public_prekey, PUBLIC_KEY_SIZE) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate invalid public prekey.");
	}
	status = prekey_store_get_prekey(store, public_prekey, private_prekey1);
	if (status.status == SUCCESS) {
		throw(GENERIC_ERROR, "Didn't complain about invalid public key.");
	}
	printf("Detected invalid public prekey!\n");
	//reset return status
	return_status_destroy_errors(&status);
	status.status = SUCCESS;

	//Protobuf-C export
	printf("Protobuf-C export\n");
	status = protobuf_export(
		store,
		&protobuf_export_prekeys,
		&protobuf_export_prekeys_size,
		&protobuf_export_prekeys_buffers,
		&protobuf_export_deprecated_prekeys,
		&protobuf_export_deprecated_prekeys_size,
		&protobuf_export_deprecated_prekeys_buffers);
	throw_on_error(EXPORT_ERROR, "Failed to export prekey store to protobuf.");

	printf("Prekeys:\n");
	puts("[\n");
	for (size_t i = 0; i < protobuf_export_prekeys_size; i++) {
		print_hex(protobuf_export_prekeys_buffers[i]);
		puts(",\n");
	}
	puts("]\n\n");

	printf("Deprecated Prekeys:\n");
	puts("[\n");
	for (size_t i = 0; i < protobuf_export_deprecated_prekeys_size; i++) {
		print_hex(protobuf_export_deprecated_prekeys_buffers[i]);
		puts(",\n");
	}
	puts("]\n\n");

	prekey_store_destroy(store);
	store = NULL;

	printf("Import from Protobuf-C\n");
	status = protobuf_import(
		&store,
		protobuf_export_prekeys_buffers,
		protobuf_export_prekeys_size,
		protobuf_export_deprecated_prekeys_buffers,
		protobuf_export_deprecated_prekeys_size);
	throw_on_error(IMPORT_ERROR, "Failed to import from protobuf.");

	printf("Protobuf-C export again\n");
	status = protobuf_export(
		store,
		&protobuf_second_export_prekeys,
		&protobuf_second_export_prekeys_size,
		&protobuf_second_export_prekeys_buffers,
		&protobuf_second_export_deprecated_prekeys,
		&protobuf_second_export_deprecated_prekeys_size,
		&protobuf_second_export_deprecated_prekeys_buffers);
	throw_on_error(EXPORT_ERROR, "Failed to export prekey store to protobuf.");

	//compare both prekey lists
	printf("Compare normal prekeys\n");
	if (protobuf_export_prekeys_size != protobuf_second_export_prekeys_size) {
		throw(INCORRECT_DATA, "Both prekey exports contain different amounts of keys.");
	}
	for (size_t i = 0; i < protobuf_export_prekeys_size; i++) {
		if (buffer_compare(protobuf_export_prekeys_buffers[i], protobuf_second_export_prekeys_buffers[i]) != 0) {
			throw(INCORRECT_DATA, "First and second prekey export are not identical.");
		}
	}

	//compare both deprecated prekey lists
	printf("Compare deprecated prekeys\n");
	if (protobuf_export_deprecated_prekeys_size != protobuf_second_export_deprecated_prekeys_size) {
		throw(INCORRECT_DATA, "Both depcated prekey exports contain different amounts of keys.");
	}
	for (size_t i = 0; i < protobuf_export_deprecated_prekeys_size; i++) {
		if (buffer_compare(protobuf_export_deprecated_prekeys_buffers[i], protobuf_second_export_deprecated_prekeys_buffers[i]) != 0) {
			throw(INCORRECT_DATA, "First and second deprecated prekey export are not identical.");
		}
	}

	//test the automatic deprecation of old keys
	if (buffer_clone(public_prekey, store->prekeys[PREKEY_AMOUNT-1].public_key) != 0) {
		throw(BUFFER_ERROR, "Failed to clone public key.");
	}

	store->prekeys[PREKEY_AMOUNT-1].expiration_date -= 365 * 24 * 3600; //one year
	store->oldest_expiration_date = store->prekeys[PREKEY_AMOUNT - 1].expiration_date;

	status = prekey_store_rotate(store);
	throw_on_error(GENERIC_ERROR, "Failed to rotate the prekeys.");

	if (buffer_compare(store->deprecated_prekeys->public_key, public_prekey) != 0) {
		throw(GENERIC_ERROR, "Failed to deprecate outdated key.");
	}
	printf("Successfully deprecated outdated key!\n");

	//test the automatic removal of old deprecated keys!
	if (buffer_clone(public_prekey, store->deprecated_prekeys->next->public_key) != 0) {
		throw(BUFFER_ERROR, "Failed to clone public key.");
	}

	store->deprecated_prekeys->next->expiration_date -= 24 * 3600;
	store->oldest_deprecated_expiration_date = store->deprecated_prekeys->next->expiration_date;

	status = prekey_store_rotate(store);
	throw_on_error(GENERIC_ERROR, "Failed to rotate the prekeys.");

	if (store->deprecated_prekeys->next != NULL) {
		throw(GENERIC_ERROR, "Failed to remove outdated key.");
	}
	printf("Successfully removed outdated deprecated key!\n");

	status = protobuf_no_deprecated_keys();
	throw_on_error(GENERIC_ERROR, "Failed to im-/export a prekey store without deprecated prekeys.");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(public_prekey);
	buffer_destroy_from_heap_and_null_if_valid(private_prekey1);
	buffer_destroy_from_heap_and_null_if_valid(private_prekey2);
	buffer_destroy_from_heap_and_null_if_valid(prekey_list);
	prekey_store_destroy(store);

	if (protobuf_export_prekeys != NULL) {
		for (size_t i = 0; i < protobuf_export_prekeys_size; i++) {
			if (protobuf_export_prekeys[i] != NULL) {
				prekey__free_unpacked(protobuf_export_prekeys[i], &protobuf_c_allocators);
				protobuf_export_prekeys[i] = NULL;
			}

		}
		zeroed_free_and_null_if_valid(protobuf_export_prekeys);
	}

	if (protobuf_export_deprecated_prekeys != NULL) {
		for (size_t i = 0; i < protobuf_export_deprecated_prekeys_size; i++) {
			if (protobuf_export_deprecated_prekeys[i] != NULL) {
				prekey__free_unpacked(protobuf_export_deprecated_prekeys[i], &protobuf_c_allocators);
				protobuf_export_deprecated_prekeys[i] = NULL;
			}
		}

		zeroed_free_and_null_if_valid(protobuf_export_deprecated_prekeys);
	}

	if (protobuf_export_prekeys_buffers != NULL) {
		for (size_t i = 0; i < protobuf_export_prekeys_size; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_export_prekeys_buffers[i]);
		}

		zeroed_free_and_null_if_valid(protobuf_export_prekeys_buffers);
	}

	if (protobuf_export_deprecated_prekeys_buffers != NULL) {
		for (size_t i = 0; i < protobuf_export_deprecated_prekeys_size; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_export_deprecated_prekeys_buffers[i]);
		}

		zeroed_free_and_null_if_valid(protobuf_export_deprecated_prekeys_buffers);
	}

	if (protobuf_second_export_prekeys != NULL) {
		for (size_t i = 0; i < protobuf_second_export_prekeys_size; i++) {
			if (protobuf_second_export_prekeys[i] != NULL) {
				prekey__free_unpacked(protobuf_second_export_prekeys[i], &protobuf_c_allocators);
				protobuf_second_export_prekeys[i] = NULL;
			}

		}
		zeroed_free_and_null_if_valid(protobuf_second_export_prekeys);
	}

	if (protobuf_second_export_deprecated_prekeys != NULL) {
		for (size_t i = 0; i < protobuf_second_export_deprecated_prekeys_size; i++) {
			if (protobuf_second_export_deprecated_prekeys[i] != NULL) {
				prekey__free_unpacked(protobuf_second_export_deprecated_prekeys[i], &protobuf_c_allocators);
				protobuf_second_export_deprecated_prekeys[i] = NULL;
			}
		}

		zeroed_free_and_null_if_valid(protobuf_second_export_deprecated_prekeys);
	}

	if (protobuf_second_export_prekeys_buffers != NULL) {
		for (size_t i = 0; i < protobuf_second_export_prekeys_size; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_prekeys_buffers[i]);
		}

		zeroed_free_and_null_if_valid(protobuf_second_export_prekeys_buffers);
	}

	if (protobuf_second_export_deprecated_prekeys_buffers != NULL) {
		for (size_t i = 0; i < protobuf_second_export_deprecated_prekeys_size; i++) {
			buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_deprecated_prekeys_buffers[i]);
		}

		zeroed_free_and_null_if_valid(protobuf_second_export_deprecated_prekeys_buffers);
	}

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
