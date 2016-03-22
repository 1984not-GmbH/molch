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

	prekey_store *store = prekey_store_create();
	if (store == NULL) {
		fprintf(stderr, "ERROR: Failed to create a prekey store!\n");
		return EXIT_FAILURE;
	}

	buffer_t *public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *private_prekey1 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *private_prekey2 = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *prekey_list = buffer_create_on_heap(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);

	int status = 0;
	status = prekey_store_list(store, prekey_list);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to list prekey (%i)!\n", status);
		goto cleanup;
	}
	printf("Prekey list:\n");
	print_hex(prekey_list);
	putchar('\n');

	//compare the public keys with the ones in the prekey store
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare_partial(prekey_list, PUBLIC_KEY_SIZE * i, store->prekeys[i].public_key, 0, PUBLIC_KEY_SIZE) != 0) {
			fprintf(stderr, "ERROR: Key list doesn't match the prekey store.\n");
			status = EXIT_FAILURE;
			goto cleanup;
		}
	}
	printf("Prekey list matches the prekey store!\n");

	//get a private key
	const size_t prekey_index = 10;
	status = buffer_clone(public_prekey, store->prekeys[prekey_index].public_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone public key! (%i)\n", status);
		goto cleanup;
	}

	status = prekey_store_get_prekey(store, public_prekey, private_prekey1);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get prekey. (%i)\n", status);
		goto cleanup;
	}
	printf("Get a Prekey:\n");
	printf("Public key:\n");
	print_hex(public_prekey);
	printf("Private key:\n");
	print_hex(private_prekey1);
	putchar('\n');

	if (store->deprecated_prekeys == NULL) {
		fprintf(stderr, "ERROR: Failed to deprecate requested key!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	if ((buffer_compare(public_prekey, store->deprecated_prekeys->public_key) != 0)
			|| (buffer_compare(private_prekey1, store->deprecated_prekeys->private_key) != 0)) {
		fprintf(stderr, "ERROR: Deprecated key is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	if (buffer_compare(store->prekeys[prekey_index].public_key, public_prekey) == 0) {
		fprintf(stderr, "ERROR: Failed to generate new key for deprecated one!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully deprecated requested key!\n");

	//check if the prekey can be obtained from the deprecated keys
	status = prekey_store_get_prekey(store, public_prekey, private_prekey2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get key from the deprecated area! (%i)\n", status);
		goto cleanup;
	}

	if (buffer_compare(private_prekey1, private_prekey2) != 0) {
		fprintf(stderr, "ERROR: Prekey from the deprecated area didn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully got prekey from the deprecated area!\n");

	//try to get a nonexistent key
	status = buffer_fill_random(public_prekey, PUBLIC_KEY_SIZE);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate invalid public prekey! (%i)\n", status);
		goto cleanup;
	}
	if (prekey_store_get_prekey(store, public_prekey, private_prekey1) == 0) {
		fprintf(stderr, "ERROR: Didn't complain about invalid public key!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Detected invalid public prekey!\n");

	//Test JSON Export!
	JSON_EXPORT(json_string, 100000, 10000, true, store, prekey_store_json_export);
	if (json_string == NULL) {
		fprintf(stderr, "ERROR: Failed to export to JSON!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("%.*s\n", (int)json_string->content_length, (char*)json_string->content);
	prekey_store_destroy(store);

	//Import it again
	JSON_IMPORT(store, 100000, json_string, prekey_store_json_import);
	if (store == NULL) {
		fprintf(stderr, "ERROR: Failed to import from JSON!\n");
		status = EXIT_FAILURE;
		buffer_destroy_from_heap(json_string);
		goto cleanup;
	}

	//Export it again
	JSON_EXPORT(json_string2, 100000, 10000, true, store, prekey_store_json_export);
	if (json_string2 == NULL) {
		fprintf(stderr, "ERROR: Failed to export imported JSON.!\n");
		status = EXIT_FAILURE;
		buffer_destroy_from_heap(json_string);
		goto cleanup;
	}

	//compare both
	if (buffer_compare(json_string, json_string2) != 0) {
		fprintf(stderr, "ERROR: Imported JSON is incorrect!\n");
		status = EXIT_FAILURE;
		buffer_destroy_from_heap(json_string);
		buffer_destroy_from_heap(json_string2);
		goto cleanup;
	}

	buffer_destroy_from_heap(json_string);
	buffer_destroy_from_heap(json_string2);

	//test the automatic deprecation of old keys
	status = buffer_clone(public_prekey, store->prekeys[PREKEY_AMOUNT-1].public_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone public key!\n");
		goto cleanup;
	}

	store->prekeys[PREKEY_AMOUNT-1].timestamp -= 365 * 24 * 3600; //one year
	store->oldest_timestamp = store->prekeys[PREKEY_AMOUNT - 1].timestamp;

	status = prekey_store_rotate(store);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to rotate the prekeys!\n");
		goto cleanup;
	}

	if (buffer_compare(store->deprecated_prekeys->public_key, public_prekey) != 0) {
		fprintf(stderr, "ERROR: Failed to deprecate outdated key!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully deprecated outdated key!\n");

	//test the automatic removal of old deprecated keys!
	status = buffer_clone(public_prekey, store->deprecated_prekeys->next->public_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone public key!\n");
		goto cleanup;
	}

	store->deprecated_prekeys->next->timestamp -= 24 * 3600;
	store->oldest_deprecated_timestamp = store->deprecated_prekeys->next->timestamp;

	status = prekey_store_rotate(store);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to rotate the prekeys!\n");
		goto cleanup;
	}

	if (store->deprecated_prekeys->next != NULL) {
		fprintf(stderr, "ERROR: Failed to remove outdated key!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully removed outdated deprecated key!\n");

cleanup:
	buffer_destroy_from_heap(public_prekey);
	buffer_destroy_from_heap(private_prekey1);
	buffer_destroy_from_heap(private_prekey2);
	buffer_destroy_from_heap(prekey_list);
	prekey_store_destroy(store);

	return status;
}
