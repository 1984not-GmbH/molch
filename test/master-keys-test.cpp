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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>

#include "../lib/master-keys.h"
#include "../lib/constants.h"
#include "utils.h"

return_status protobuf_export(
		MasterKeys& keys,
		Buffer*& public_signing_key_buffer,
		Buffer*& private_signing_key_buffer,
		Buffer*& public_identity_key_buffer,
		Buffer*& private_identity_key_buffer) __attribute__((warn_unused_result));
return_status protobuf_export(
		MasterKeys& keys,
		Buffer*& public_signing_key_buffer,
		Buffer*& private_signing_key_buffer,
		Buffer*& public_identity_key_buffer,
		Buffer*& private_identity_key_buffer) {
	return_status status = return_status_init();

	Key * public_signing_key = nullptr;
	Key * private_signing_key = nullptr;
	Key * public_identity_key = nullptr;
	Key * private_identity_key = nullptr;

	status = keys.exportMasterKeys(public_signing_key, private_signing_key, public_identity_key, private_identity_key);
	THROW_on_error(EXPORT_ERROR, "Failed to export master keys.");

	//export the keys
	//public signing key
	{
		size_t public_signing_key_proto_size = key__get_packed_size(public_signing_key);
		public_signing_key_buffer = Buffer::create(public_signing_key_proto_size, 0);
		public_signing_key_buffer->content_length = key__pack(public_signing_key, public_signing_key_buffer->content);
		if (public_signing_key_buffer->content_length != public_signing_key_proto_size) {
			THROW(EXPORT_ERROR, "Failed to export public signing key.");
		}
	}

	//private signing key
	{
		size_t private_signing_key_proto_size = key__get_packed_size(private_signing_key);
		private_signing_key_buffer = Buffer::create(private_signing_key_proto_size, 0);
		private_signing_key_buffer->content_length = key__pack(private_signing_key, private_signing_key_buffer->content);
		if (private_signing_key_buffer->content_length != private_signing_key_proto_size) {
			THROW(EXPORT_ERROR, "Failed to export private signing key.");
		}
	}

	//public identity key
	{
		size_t public_identity_key_proto_size = key__get_packed_size(public_identity_key);
		public_identity_key_buffer = Buffer::create(public_identity_key_proto_size, 0);
		public_identity_key_buffer->content_length = key__pack(public_identity_key, public_identity_key_buffer->content);
		if (public_identity_key_buffer->content_length != public_identity_key_proto_size) {
			THROW(EXPORT_ERROR, "Failed to export public identity key.");
		}
	}

	//private identity key
	{
		size_t private_identity_key_proto_size = key__get_packed_size(private_identity_key);
		private_identity_key_buffer = Buffer::create(private_identity_key_proto_size, 0);
		private_identity_key_buffer->content_length = key__pack(private_identity_key, private_identity_key_buffer->content);
		if (private_identity_key_buffer->content_length != private_identity_key_proto_size) {
			THROW(EXPORT_ERROR, "Failed to export private identity key.");
		}
	}

cleanup:
	if (public_signing_key != nullptr) {
		key__free_unpacked(public_signing_key, &protobuf_c_allocators);
		public_signing_key = nullptr;
	}

	if (private_signing_key != nullptr) {
		key__free_unpacked(private_signing_key, &protobuf_c_allocators);
		private_signing_key = nullptr;
	}

	if (public_identity_key != nullptr) {
		key__free_unpacked(public_identity_key, &protobuf_c_allocators);
		public_identity_key = nullptr;
	}

	if (private_identity_key != nullptr) {
		key__free_unpacked(private_identity_key, &protobuf_c_allocators);
		private_identity_key = nullptr;
	}

	//cleanup of buffers is done in the main function
	return status;
}


return_status protobuf_import(
		MasterKeys*& keys,
		const Buffer& public_signing_key_buffer,
		const Buffer& private_signing_key_buffer,
		const Buffer& public_identity_key_buffer,
		const Buffer& private_identity_key_buffer) __attribute__((warn_unused_result));
return_status protobuf_import(
		MasterKeys*& keys,
		const Buffer& public_signing_key_buffer,
		const Buffer& private_signing_key_buffer,
		const Buffer& public_identity_key_buffer,
		const Buffer& private_identity_key_buffer) {
	return_status status = return_status_init();

	Key *public_signing_key = nullptr;
	Key *private_signing_key = nullptr;
	Key *public_identity_key = nullptr;
	Key *private_identity_key = nullptr;

	//unpack the protobuf-c buffers
	public_signing_key = key__unpack(
		&protobuf_c_allocators,
		public_signing_key_buffer.content_length,
		public_signing_key_buffer.content);
	if (public_signing_key == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack public signing key from protobuf.");
	}
	private_signing_key = key__unpack(
		&protobuf_c_allocators,
		private_signing_key_buffer.content_length,
		private_signing_key_buffer.content);
	if (private_signing_key == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack private signing key from protobuf.");
	}
	public_identity_key = key__unpack(
		&protobuf_c_allocators,
		public_identity_key_buffer.content_length,
		public_identity_key_buffer.content);
	if (public_identity_key == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack public identity key from protobuf.");
	}
	private_identity_key = key__unpack(
		&protobuf_c_allocators,
		private_identity_key_buffer.content_length,
		private_identity_key_buffer.content);
	if (private_identity_key == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack private identity key from protobuf.");
	}

	status = MasterKeys::import(
		keys,
		public_signing_key,
		private_signing_key,
		public_identity_key,
		private_identity_key);
	THROW_on_error(IMPORT_ERROR, "Failed to import master keys.")
cleanup:
	on_error {
		sodium_free_and_null_if_valid(keys);
	}

	//free the protobuf-c structs
	if (public_signing_key != nullptr) {
		key__free_unpacked(public_signing_key, &protobuf_c_allocators);
		public_signing_key = nullptr;
	}
	if (private_signing_key != nullptr) {
		key__free_unpacked(private_signing_key, &protobuf_c_allocators);
		private_signing_key = nullptr;
	}
	if (public_identity_key != nullptr) {
		key__free_unpacked(public_identity_key, &protobuf_c_allocators);
		public_identity_key = nullptr;
	}
	if (private_identity_key != nullptr) {
		key__free_unpacked(private_identity_key, &protobuf_c_allocators);
		private_identity_key = nullptr;
	}

	//buffers will be freed in main

	return status;
}


int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	MasterKeys *unspiced_master_keys = nullptr;
	MasterKeys *spiced_master_keys = nullptr;
	MasterKeys *imported_master_keys = nullptr;

	//public key buffers
	Buffer *public_signing_key = Buffer::create(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	Buffer *public_identity_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	Buffer *signed_data = Buffer::create(100, 0);
	Buffer *unwrapped_data = Buffer::create(100, 0);

	//export buffers
	Buffer *protobuf_export_public_signing_key = nullptr;
	Buffer *protobuf_export_private_signing_key = nullptr;
	Buffer *protobuf_export_public_identity_key = nullptr;
	Buffer *protobuf_export_private_identity_key = nullptr;
	//second export
	Buffer *protobuf_second_export_public_signing_key = nullptr;
	Buffer *protobuf_second_export_private_signing_key = nullptr;
	Buffer *protobuf_second_export_public_identity_key = nullptr;
	Buffer *protobuf_second_export_private_identity_key = nullptr;

	int status_int = 0;

	//create the unspiced master keys
	status = MasterKeys::create(unspiced_master_keys, nullptr, nullptr, nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to create unspiced master keys.");

	//get the public keys
	status = unspiced_master_keys->getSigningKey(*public_signing_key);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to get the public signing key!");
	status = unspiced_master_keys->getIdentityKey(*public_identity_key);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to get the public identity key.");

	//print the keys
	sodium_mprotect_readonly(unspiced_master_keys);
	printf("Signing keypair:\n");
	printf("Public:\n");
	print_hex(&unspiced_master_keys->public_signing_key);

	printf("\nPrivate:\n");
	print_hex(&unspiced_master_keys->private_signing_key);

	printf("\n\nIdentity keys:\n");
	printf("Public:\n");
	print_hex(&unspiced_master_keys->public_identity_key);

	printf("\nPrivate:\n");
	print_hex(&unspiced_master_keys->private_identity_key);

	//check the exported public keys
	if (public_signing_key->compare(&unspiced_master_keys->public_signing_key) != 0) {
		THROW(INCORRECT_DATA, "Exported public signing key doesn't match.");
	}
	if (public_identity_key->compare(&unspiced_master_keys->public_identity_key) != 0) {
		THROW(INCORRECT_DATA, "Exported public identity key doesn't match.");
	}
	sodium_mprotect_noaccess(unspiced_master_keys);


	//create the spiced master keys
	buffer_create_from_string(seed, ";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk");
	status = MasterKeys::create(spiced_master_keys, seed, public_signing_key, public_identity_key);
	THROW_on_error(CREATION_ERROR, "Failed to create spiced master keys.");

	//print the keys
	sodium_mprotect_readonly(spiced_master_keys);
	printf("Signing keypair:\n");
	printf("Public:\n");
	print_hex(&spiced_master_keys->public_signing_key);

	printf("\nPrivate:\n");
	print_hex(&spiced_master_keys->private_signing_key);

	printf("\n\nIdentity keys:\n");
	printf("Public:\n");
	print_hex(&spiced_master_keys->public_identity_key);

	printf("\nPrivate:\n");
	print_hex(&spiced_master_keys->private_identity_key);

	//check the exported public keys
	if (public_signing_key->compare(&spiced_master_keys->public_signing_key) != 0) {
		THROW(INCORRECT_DATA, "Exported public signing key doesn't match.");
	}
	if (public_identity_key->compare(&spiced_master_keys->public_identity_key) != 0) {
		THROW(INCORRECT_DATA, "Exported public identity key doesn't match.");
	}
	sodium_mprotect_noaccess(spiced_master_keys);

	//sign some data
	buffer_create_from_string(data, "This is some data to be signed.");
	printf("Data to be signed.\n");
	printf("%.*s\n", (int)data->content_length, (char*)data->content);

	status = spiced_master_keys->sign(*data, *signed_data);
	THROW_on_error(SIGN_ERROR, "Failed to sign data.");
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
		THROW(VERIFY_ERROR, "Failed to verify signature.");
	}
	unwrapped_data->content_length = (size_t) unwrapped_data_length;

	printf("\nSignature was successfully verified!\n");

	//Test Export to Protobuf-C
	printf("Export to Protobuf-C:\n");

	status = protobuf_export(
		*spiced_master_keys,
		protobuf_export_public_signing_key,
		protobuf_export_private_signing_key,
		protobuf_export_public_identity_key,
		protobuf_export_private_identity_key);
	THROW_on_error(EXPORT_ERROR, "Failed to export spiced master keys.");

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
		spiced_master_keys,
		*protobuf_export_public_signing_key,
		*protobuf_export_private_signing_key,
		*protobuf_export_public_identity_key,
		*protobuf_export_private_identity_key);
	THROW_on_error(IMPORT_ERROR, "Failed to import from Protobuf-C.");

	//export again
	status = protobuf_export(
		*spiced_master_keys,
		protobuf_second_export_public_signing_key,
		protobuf_second_export_private_signing_key,
		protobuf_second_export_public_identity_key,
		protobuf_second_export_private_identity_key);
	THROW_on_error(EXPORT_ERROR, "Failed to export spiced master keys.");

	//now compare
	if (protobuf_export_public_signing_key->compare(protobuf_second_export_public_signing_key) != 0) {
		THROW(INCORRECT_DATA, "The public signing keys do not match.");
	}
	if (protobuf_export_private_signing_key->compare(protobuf_second_export_private_signing_key) != 0) {
		THROW(INCORRECT_DATA, "The private signing keys do not match.");
	}
	if (protobuf_export_public_identity_key->compare(protobuf_second_export_public_identity_key) != 0) {
		THROW(INCORRECT_DATA, "The public identity keys do not match.");
	}
	if (protobuf_export_private_identity_key->compare(protobuf_second_export_private_identity_key) != 0) {
		THROW(INCORRECT_DATA, "The private identity keys do not match.");
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
