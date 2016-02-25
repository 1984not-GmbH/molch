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
#include "utils.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	master_keys *unspiced_master_keys = NULL;
	master_keys *spiced_master_keys = NULL;

	//public key buffers
	buffer_t *public_signing_key = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	buffer_t *signed_data = buffer_create_on_heap(100, 0);
	buffer_t *unwrapped_data = buffer_create_on_heap(100, 0);

	int status = 0;

	//create the unspiced master keys
	unspiced_master_keys = master_keys_create(NULL, NULL, NULL);
	if (unspiced_master_keys == NULL) {
		fprintf(stderr, "ERROR: Failed to create unspiced master keys!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//get the public keys
	status = master_keys_get_signing_key(unspiced_master_keys, public_signing_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get the public signing key! (%i)\n", status);
		goto cleanup;
	}
	status = master_keys_get_identity_key(unspiced_master_keys, public_identity_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get the public identity key! (%i)\n", status);
		goto cleanup;
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
		fprintf(stderr, "ERROR: Exported public signing key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if (buffer_compare(public_identity_key, unspiced_master_keys->public_identity_key) != 0) {
		fprintf(stderr, "ERROR: Exported public identity key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(unspiced_master_keys);


	//create the spiced master keys
	buffer_create_from_string(seed, ";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk");
	spiced_master_keys = master_keys_create(seed, public_signing_key, public_identity_key);
	if (spiced_master_keys == NULL) {
		fprintf(stderr, "ERROR: Failed to create spiced master keys!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

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
		fprintf(stderr, "ERROR: Exported public signing key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	if (buffer_compare(public_identity_key, spiced_master_keys->public_identity_key) != 0) {
		fprintf(stderr, "ERROR: Exported public identity key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	sodium_mprotect_noaccess(spiced_master_keys);

	//sign some data
	buffer_create_from_string(data, "This is some data to be signed.");
	printf("Data to be signed.\n");
	printf("%.*s\n", (int)data->content_length, (char*)data->content);

	status = master_keys_sign(
			spiced_master_keys,
			data,
			signed_data);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to sign data!\n");
		goto cleanup;
	}
	printf("Signed data:\n");
	print_hex(signed_data);

	//now check the signature
	unsigned long long unwrapped_data_length;
	status = crypto_sign_open(
			unwrapped_data->content,
			&unwrapped_data_length,
			signed_data->content,
			signed_data->content_length,
			public_signing_key->content);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to verify signature!\n");
		goto cleanup;
	}
	unwrapped_data->content_length = (size_t) unwrapped_data_length;

	printf("\nSignature was successfully verified!\n");

cleanup:
	if (unspiced_master_keys != NULL) {
		sodium_free(unspiced_master_keys);
	}
	if (spiced_master_keys != NULL) {
		sodium_free(spiced_master_keys);
	}

	buffer_destroy_from_heap(public_signing_key);
	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(signed_data);
	buffer_destroy_from_heap(unwrapped_data);

	return status;
}
