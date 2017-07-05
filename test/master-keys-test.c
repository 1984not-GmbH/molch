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

#include "../lib/master-keys.h"
#include "../lib/constants.h"
#include "utils.h"

return_status protobuf_export(
		master_keys * const keys,
		buffer_t ** const public_signing_key_buffer,
		buffer_t ** const private_signing_key_buffer,
		buffer_t ** const public_identity_key_buffer,
		buffer_t ** const private_identity_key_buffer) __attribute__((warn_unused_result));
return_status protobuf_export(
		master_keys * const keys,
		buffer_t ** const public_signing_key_buffer,
		buffer_t ** const private_signing_key_buffer,
		buffer_t ** const public_identity_key_buffer,
		buffer_t ** const private_identity_key_buffer) {
	return_status status = return_status_init();

	Key * public_signing_key = NULL;
	Key * private_signing_key = NULL;
	Key * public_identity_key = NULL;
	Key * private_identity_key = NULL;

	//check input
	if ((keys == NULL)
			|| (public_signing_key_buffer == NULL) || (private_signing_key_buffer == NULL)
			|| (public_identity_key_buffer == NULL) || (private_identity_key_buffer == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	status = master_keys_export(
			keys,
			&public_signing_key,
			&private_signing_key,
			&public_identity_key,
			&private_identity_key);
	throw_on_error(EXPORT_ERROR, "Failed to export master keys.");

	//export the keys
	//public signing key
	size_t public_signing_key_proto_size = key__get_packed_size(public_signing_key);
	*public_signing_key_buffer = buffer_create_on_heap(public_signing_key_proto_size, 0);
	(*public_signing_key_buffer)->content_length = key__pack(public_signing_key, (*public_signing_key_buffer)->content);
	if ((*public_signing_key_buffer)->content_length != public_signing_key_proto_size) {
		throw(EXPORT_ERROR, "Failed to export public signing key.");
	}

	//private signing key
	size_t private_signing_key_proto_size = key__get_packed_size(private_signing_key);
	*private_signing_key_buffer = buffer_create_on_heap(private_signing_key_proto_size, 0);
	(*private_signing_key_buffer)->content_length = key__pack(private_signing_key, (*private_signing_key_buffer)->content);
	if ((*private_signing_key_buffer)->content_length != private_signing_key_proto_size) {
		throw(EXPORT_ERROR, "Failed to export private signing key.");
	}

	//public identity key
	size_t public_identity_key_proto_size = key__get_packed_size(public_identity_key);
	*public_identity_key_buffer = buffer_create_on_heap(public_identity_key_proto_size, 0);
	(*public_identity_key_buffer)->content_length = key__pack(public_identity_key, (*public_identity_key_buffer)->content);
	if ((*public_identity_key_buffer)->content_length != public_identity_key_proto_size) {
		throw(EXPORT_ERROR, "Failed to export public identity key.");
	}

	//private identity key
	size_t private_identity_key_proto_size = key__get_packed_size(private_identity_key);
	*private_identity_key_buffer = buffer_create_on_heap(private_identity_key_proto_size, 0);
	(*private_identity_key_buffer)->content_length = key__pack(private_identity_key, (*private_identity_key_buffer)->content);
	if ((*private_identity_key_buffer)->content_length != private_identity_key_proto_size) {
		throw(EXPORT_ERROR, "Failed to export private identity key.");
	}

cleanup:
	if (public_signing_key != NULL) {
		key__free_unpacked(public_signing_key, &protobuf_c_allocators);
		public_signing_key = NULL;
	}

	if (private_signing_key != NULL) {
		key__free_unpacked(private_signing_key, &protobuf_c_allocators);
		private_signing_key = NULL;
	}

	if (public_identity_key != NULL) {
		key__free_unpacked(public_identity_key, &protobuf_c_allocators);
		public_identity_key = NULL;
	}

	if (private_identity_key != NULL) {
		key__free_unpacked(private_identity_key, &protobuf_c_allocators);
		private_identity_key = NULL;
	}

	//cleanup of buffers is done in the main function
	return status;
}


return_status protobuf_import(
		master_keys ** const keys,
		const buffer_t * const public_signing_key_buffer,
		const buffer_t * const private_signing_key_buffer,
		const buffer_t * const public_identity_key_buffer,
		const buffer_t * const private_identity_key_buffer) __attribute__((warn_unused_result));
return_status protobuf_import(
		master_keys ** const keys,
		const buffer_t * const public_signing_key_buffer,
		const buffer_t * const private_signing_key_buffer,
		const buffer_t * const public_identity_key_buffer,
		const buffer_t * const private_identity_key_buffer) {
	return_status status = return_status_init();

	Key *public_signing_key = NULL;
	Key *private_signing_key = NULL;
	Key *public_identity_key = NULL;
	Key *private_identity_key = NULL;

	//check inputs
	if ((keys == NULL)
			|| (public_signing_key_buffer == NULL)
			|| (private_signing_key_buffer == NULL)
			|| (public_identity_key_buffer == NULL)
			|| (private_identity_key_buffer == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	//unpack the protobuf-c buffers
	public_signing_key = key__unpack(
		&protobuf_c_allocators,
		public_signing_key_buffer->content_length,
		public_signing_key_buffer->content);
	if (public_signing_key == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack public signing key from protobuf.");
	}
	private_signing_key = key__unpack(
		&protobuf_c_allocators,
		private_signing_key_buffer->content_length,
		private_signing_key_buffer->content);
	if (private_signing_key == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack private signing key from protobuf.");
	}
	public_identity_key = key__unpack(
		&protobuf_c_allocators,
		public_identity_key_buffer->content_length,
		public_identity_key_buffer->content);
	if (public_identity_key == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack public identity key from protobuf.");
	}
	private_identity_key = key__unpack(
		&protobuf_c_allocators,
		private_identity_key_buffer->content_length,
		private_identity_key_buffer->content);
	if (private_identity_key == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack private identity key from protobuf.");
	}

	status = master_keys_import(
		keys,
		public_signing_key,
		private_signing_key,
		public_identity_key,
		private_identity_key);
	throw_on_error(IMPORT_ERROR, "Failed to import master keys.")
cleanup:
	on_error {
		if (keys != NULL) {
			sodium_free_and_null_if_valid(*keys);
		}
	}

	//free the protobuf-c structs
	if (public_signing_key != NULL) {
		key__free_unpacked(public_signing_key, &protobuf_c_allocators);
		public_signing_key = NULL;
	}
	if (private_signing_key != NULL) {
		key__free_unpacked(private_signing_key, &protobuf_c_allocators);
		private_signing_key = NULL;
	}
	if (public_identity_key != NULL) {
		key__free_unpacked(public_identity_key, &protobuf_c_allocators);
		public_identity_key = NULL;
	}
	if (private_identity_key != NULL) {
		key__free_unpacked(private_identity_key, &protobuf_c_allocators);
		private_identity_key = NULL;
	}

	//buffers will be freed in main

	return status;
}


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

	//export buffers
	buffer_t *protobuf_export_public_signing_key = NULL;
	buffer_t *protobuf_export_private_signing_key = NULL;
	buffer_t *protobuf_export_public_identity_key = NULL;
	buffer_t *protobuf_export_private_identity_key = NULL;
	//second export
	buffer_t *protobuf_second_export_public_signing_key = NULL;
	buffer_t *protobuf_second_export_private_signing_key = NULL;
	buffer_t *protobuf_second_export_public_identity_key = NULL;
	buffer_t *protobuf_second_export_private_identity_key = NULL;

	int status_int = 0;

	//create the unspiced master keys
	status = master_keys_create(&unspiced_master_keys, NULL, NULL, NULL);
	throw_on_error(CREATION_ERROR, "Failed to create unspiced master keys.");

	//get the public keys
	status = master_keys_get_signing_key(unspiced_master_keys, public_signing_key);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get the public signing key!");
	status = master_keys_get_identity_key(unspiced_master_keys, public_identity_key);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get the public identity key.");

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

	status = master_keys_sign(
			spiced_master_keys,
			data,
			signed_data);
	throw_on_error(SIGN_ERROR, "Failed to sign data.");
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

	//Test Export to Protobuf-C
	printf("Export to Protobuf-C:\n");

	status = protobuf_export(
		spiced_master_keys,
		&protobuf_export_public_signing_key,
		&protobuf_export_private_signing_key,
		&protobuf_export_public_identity_key,
		&protobuf_export_private_identity_key);
	throw_on_error(EXPORT_ERROR, "Failed to export spiced master keys.");

	printf("Public signing key:\n");
	print_hex(protobuf_export_public_signing_key);
	puts("\n\n");

	printf("Private signing key:\n");
	print_hex(protobuf_export_private_signing_key);
	puts("\n\n");

	printf("Public identity key:\n");
	print_hex(protobuf_export_public_identity_key);
	puts("\n\n");

	printf("Private identity key:\n");
	print_hex(protobuf_export_private_identity_key);
	puts("\n\n");

	sodium_free_and_null_if_valid(spiced_master_keys);

	//import again
	printf("Import from Protobuf-C:\n");
	status = protobuf_import(
		&spiced_master_keys,
		protobuf_export_public_signing_key,
		protobuf_export_private_signing_key,
		protobuf_export_public_identity_key,
		protobuf_export_private_identity_key);
	throw_on_error(IMPORT_ERROR, "Failed to import from Protobuf-C.");

	//export again
	status = protobuf_export(
		spiced_master_keys,
		&protobuf_second_export_public_signing_key,
		&protobuf_second_export_private_signing_key,
		&protobuf_second_export_public_identity_key,
		&protobuf_second_export_private_identity_key);
	throw_on_error(EXPORT_ERROR, "Failed to export spiced master keys.");

	//now compare
	if (buffer_compare(protobuf_export_public_signing_key, protobuf_second_export_public_signing_key) != 0) {
		throw(INCORRECT_DATA, "The public signing keys do not match.");
	}
	if (buffer_compare(protobuf_export_private_signing_key, protobuf_second_export_private_signing_key) != 0) {
		throw(INCORRECT_DATA, "The private signing keys do not match.");
	}
	if (buffer_compare(protobuf_export_public_identity_key, protobuf_second_export_public_identity_key) != 0) {
		throw(INCORRECT_DATA, "The public identity keys do not match.");
	}
	if (buffer_compare(protobuf_export_private_identity_key, protobuf_second_export_private_identity_key) != 0) {
		throw(INCORRECT_DATA, "The private identity keys do not match.");
	}

	printf("Successfully exported to Protobuf-C and imported again.");

cleanup:
	sodium_free_and_null_if_valid(unspiced_master_keys);
	sodium_free_and_null_if_valid(spiced_master_keys);
	sodium_free_and_null_if_valid(imported_master_keys);

	buffer_destroy_from_heap_and_null_if_valid(public_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(signed_data);
	buffer_destroy_from_heap_and_null_if_valid(unwrapped_data);

	//protobuf export buffers
	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_public_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_private_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_private_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_public_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_private_signing_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_private_identity_key);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
