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

#include "../lib/prekey-store.h"
#include "../lib/json.h"
#include "../lib/constants.h"
#include "utils.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	buffer_t *public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *private_prekey1 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *private_prekey2 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *prekey_list = buffer_create_on_heap(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);

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

	//Test JSON Export!
	JSON_EXPORT(json_string, 100000, 10000, true, store, prekey_store_json_export);
	if (json_string == NULL) {
		throw(EXPORT_ERROR, "Failed to export to JSON.");
	}
	printf("%.*s\n", (int)json_string->content_length, (char*)json_string->content);
	prekey_store_destroy(store);

	//Import it again
	JSON_IMPORT(store, 100000, json_string, prekey_store_json_import);
	if (store == NULL) {
		buffer_destroy_from_heap(json_string);
		throw(IMPORT_ERROR, "Failed to import from JSON.");
	}

	//Export it again
	JSON_EXPORT(json_string2, 100000, 10000, true, store, prekey_store_json_export);
	if (json_string2 == NULL) {
		buffer_destroy_from_heap(json_string);
		throw(EXPORT_ERROR, "Failed to export imported JSON.");
	}

	//compare both
	if (buffer_compare(json_string, json_string2) != 0) {
		buffer_destroy_from_heap(json_string);
		buffer_destroy_from_heap(json_string2);
		throw(INCORRECT_DATA, "Imported JSON is incorrect.");
	}

	buffer_destroy_from_heap(json_string);
	buffer_destroy_from_heap(json_string2);

	//test the automatic deprecation of old keys
	if (buffer_clone(public_prekey, store->prekeys[PREKEY_AMOUNT-1].public_key) != 0) {
		throw(BUFFER_ERROR, "Failed to clone public key.");
	}

	store->prekeys[PREKEY_AMOUNT-1].timestamp -= 365 * 24 * 3600; //one year
	store->oldest_timestamp = store->prekeys[PREKEY_AMOUNT - 1].timestamp;

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

	store->deprecated_prekeys->next->timestamp -= 24 * 3600;
	store->oldest_deprecated_timestamp = store->deprecated_prekeys->next->timestamp;

	status = prekey_store_rotate(store);
	throw_on_error(GENERIC_ERROR, "Failed to rotate the prekeys.");

	if (store->deprecated_prekeys->next != NULL) {
		throw(GENERIC_ERROR, "Failed to remove outdated key.");
	}
	printf("Successfully removed outdated deprecated key!\n");

cleanup:
	buffer_destroy_from_heap(public_prekey);
	buffer_destroy_from_heap(private_prekey1);
	buffer_destroy_from_heap(private_prekey2);
	buffer_destroy_from_heap(prekey_list);
	prekey_store_destroy(store);

	if (status.status != SUCCESS) {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
