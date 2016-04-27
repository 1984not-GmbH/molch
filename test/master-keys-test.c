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

#include "../lib/master-keys.h"
#include "../lib/constants.h"
#include "../lib/json.h"
#include "utils.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	master_keys *unspiced_master_keys = NULL;
	master_keys *spiced_master_keys = NULL;
	master_keys *imported_master_keys = NULL;

	//public key buffers
	buffer_t *public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	buffer_t *signed_data = buffer_create_on_heap(100, 0);
	buffer_t *unwrapped_data = buffer_create_on_heap(100, 0);

	int status_int = 0;

	//create the unspiced master keys
	status = master_keys_create(&unspiced_master_keys, NULL, NULL, NULL);
	throw_on_error(CREATION_ERROR, "Failed to create unspiced master keys.");

	//get the public keys
	status_int = master_keys_get_signing_key(unspiced_master_keys, public_signing_key);
	if (status_int != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get the public signing key!");
	}
	status_int = master_keys_get_identity_key(unspiced_master_keys, public_identity_key);
	if (status_int != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get the public identity key.");
	}

	//print the keys
	sodium_mprotect_readonly(unspiced_master_keys);
	printf("Signing keypair:\n");
	printf("Public:\n");
	print_hex(unspiced_master_keys->public_signing_key);

	printf("\nPrivate:\n");
	print_hex(unspiced_master_keys->private_signing_key);

	printf("\n\nIdentity keys:\n");
	printf("Public:\n");
	print_hex(unspiced_master_keys->public_identity_key);

	printf("\nPrivate:\n");
	print_hex(unspiced_master_keys->private_identity_key);

	//check the exported public keys
	if (buffer_compare(public_signing_key, unspiced_master_keys->public_signing_key) != 0) {
		throw(INCORRECT_DATA, "Exported public signing key doesn't match.");
	}
	if (buffer_compare(public_identity_key, unspiced_master_keys->public_identity_key) != 0) {
		throw(INCORRECT_DATA, "Exported public identity key doesn't match.");
	}
	sodium_mprotect_noaccess(unspiced_master_keys);


	//create the spiced master keys
	buffer_create_from_string(seed, ";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk");
	status = master_keys_create(&spiced_master_keys, seed, public_signing_key, public_identity_key);
	throw_on_error(CREATION_ERROR, "Failed to create spiced master keys.");

	//print the keys
	sodium_mprotect_readonly(spiced_master_keys);
	printf("Signing keypair:\n");
	printf("Public:\n");
	print_hex(spiced_master_keys->public_signing_key);

	printf("\nPrivate:\n");
	print_hex(spiced_master_keys->private_signing_key);

	printf("\n\nIdentity keys:\n");
	printf("Public:\n");
	print_hex(spiced_master_keys->public_identity_key);

	printf("\nPrivate:\n");
	print_hex(spiced_master_keys->private_identity_key);

	//check the exported public keys
	if (buffer_compare(public_signing_key, spiced_master_keys->public_signing_key) != 0) {
		throw(INCORRECT_DATA, "Exported public signing key doesn't match.");
	}
	if (buffer_compare(public_identity_key, spiced_master_keys->public_identity_key) != 0) {
		throw(INCORRECT_DATA, "Exported public identity key doesn't match.");
	}
	sodium_mprotect_noaccess(spiced_master_keys);

	//sign some data
	buffer_create_from_string(data, "This is some data to be signed.");
	printf("Data to be signed.\n");
	printf("%.*s\n", (int)data->content_length, (char*)data->content);

	status_int = master_keys_sign(
			spiced_master_keys,
			data,
			signed_data);
	if (status_int != 0) {
		throw(SIGN_ERROR, "Failed to sign data.");
	}
	printf("Signed data:\n");
	print_hex(signed_data);

	//now check the signature
	unsigned long long unwrapped_data_length;
	status_int = crypto_sign_open(
			unwrapped_data->content,
			&unwrapped_data_length,
			signed_data->content,
			signed_data->content_length,
			public_signing_key->content);
	if (status_int != 0) {
		throw(VERIFY_ERROR, "Failed to verify signature.");
	}
	unwrapped_data->content_length = (size_t) unwrapped_data_length;

	printf("\nSignature was successfully verified!\n");

	//Test JSON export
	JSON_EXPORT(json_string1, 10000, 500, true, spiced_master_keys, master_keys_json_export);
	if (json_string1 == NULL) {
		throw(EXPORT_ERROR, "Failed to export to JSON.");
	}
	printf("JSON:\n");
	printf("%.*s\n", (int)json_string1->content_length, (char*)json_string1->content);

	//import it again
	JSON_IMPORT(imported_master_keys, 10000, json_string1, master_keys_json_import);
	if (imported_master_keys == NULL) {
		buffer_destroy_from_heap(json_string1);
		throw(IMPORT_ERROR, "Failed to import from JSON.")
	}
	printf("Successfully imported from JSON!\n");

	//export it again
	JSON_EXPORT(exported_json_string, 10000, 500, true, imported_master_keys, master_keys_json_export);
	if (exported_json_string == NULL) {
		buffer_destroy_from_heap(json_string1);
		throw(EXPORT_ERROR, "Failed to export imported back to JSON.");
	}
	printf("Successfully exported back to JSON!\n");

	//compare them
	if (buffer_compare(json_string1, exported_json_string) != 0) {
		buffer_destroy_from_heap(json_string1);
		buffer_destroy_from_heap(exported_json_string);
		throw(INCORRECT_DATA, "Object imported from JSON was incorrect.");
	}
	printf("Imported Object matches!\n");

	buffer_destroy_from_heap(json_string1);
	buffer_destroy_from_heap(exported_json_string);

cleanup:
	if (unspiced_master_keys != NULL) {
		sodium_free(unspiced_master_keys);
	}
	if (spiced_master_keys != NULL) {
		sodium_free(spiced_master_keys);
	}
	if (imported_master_keys != NULL) {
		sodium_free(imported_master_keys);
	}

	buffer_destroy_from_heap(public_signing_key);
	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(signed_data);
	buffer_destroy_from_heap(unwrapped_data);

	if (status.status != SUCCESS) {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
