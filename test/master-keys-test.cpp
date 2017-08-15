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
#include <memory>
#include <iostream>

#include "../lib/master-keys.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "../lib/protobuf-deleters.hpp"
#include "utils.hpp"

void protobuf_export(
		MasterKeys& keys,
		std::unique_ptr<Buffer>& public_signing_key_buffer,
		std::unique_ptr<Buffer>& private_signing_key_buffer,
		std::unique_ptr<Buffer>& public_identity_key_buffer,
		std::unique_ptr<Buffer>& private_identity_key_buffer) {
	std::unique_ptr<Key,KeyDeleter> public_signing_key;
	std::unique_ptr<Key,KeyDeleter> private_signing_key;
	std::unique_ptr<Key,KeyDeleter> public_identity_key;
	std::unique_ptr<Key,KeyDeleter> private_identity_key;

	keys.exportProtobuf(
				public_signing_key,
				private_signing_key,
				public_identity_key,
				private_identity_key);

	//copy keys to buffer
	//public signing key
	size_t public_signing_key_proto_size = key__get_packed_size(public_signing_key.get());
	public_signing_key_buffer = std::make_unique<Buffer>(public_signing_key_proto_size, 0);
	public_signing_key_buffer->content_length = key__pack(public_signing_key.get(), public_signing_key_buffer->content);
	if (!public_signing_key_buffer->contains(public_signing_key_proto_size)) {
		throw MolchException(EXPORT_ERROR, "Failed to export public signing key.");
	}

	//private signing key
	size_t private_signing_key_proto_size = key__get_packed_size(private_signing_key.get());
	private_signing_key_buffer = std::make_unique<Buffer>(private_signing_key_proto_size, 0);
	private_signing_key_buffer->content_length = key__pack(private_signing_key.get(), private_signing_key_buffer->content);
	if (!private_signing_key_buffer->contains(private_signing_key_proto_size)) {
		throw MolchException(EXPORT_ERROR, "Failed to export private signing key.");
	}

	//public identity key
	size_t public_identity_key_proto_size = key__get_packed_size(public_identity_key.get());
	public_identity_key_buffer = std::make_unique<Buffer>(public_identity_key_proto_size, 0);
	public_identity_key_buffer->content_length = key__pack(public_identity_key.get(), public_identity_key_buffer->content);
	if (!public_identity_key_buffer->contains(public_identity_key_proto_size)) {
		throw MolchException(EXPORT_ERROR, "Failed to export public identity key.");
	}

	//private identity key
	size_t private_identity_key_proto_size = key__get_packed_size(private_identity_key.get());
	private_identity_key_buffer = std::make_unique<Buffer>(private_identity_key_proto_size, 0);
	private_identity_key_buffer->content_length = key__pack(private_identity_key.get(), private_identity_key_buffer->content);
	if (!private_identity_key_buffer->contains(private_identity_key_proto_size)) {
		throw MolchException(EXPORT_ERROR, "Failed to export private identity key.");
	}
}


void protobuf_import(
		std::unique_ptr<MasterKeys>& keys,
		const Buffer& public_signing_key_buffer,
		const Buffer& private_signing_key_buffer,
		const Buffer& public_identity_key_buffer,
		const Buffer& private_identity_key_buffer) {
	//unpack the protobuf-c buffers
	auto public_signing_key = std::unique_ptr<Key,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			public_signing_key_buffer.content_length,
			public_signing_key_buffer.content));
	if (!public_signing_key) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack public signing key from protobuf.");
	}
	auto private_signing_key = std::unique_ptr<Key,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			private_signing_key_buffer.content_length,
			private_signing_key_buffer.content));
	if (!private_signing_key) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack private signing key from protobuf.");
	}
	auto public_identity_key = std::unique_ptr<Key,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			public_identity_key_buffer.content_length,
			public_identity_key_buffer.content));
	if (!public_identity_key) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack public identity key from protobuf.");
	}
	auto private_identity_key = std::unique_ptr<Key,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			private_identity_key_buffer.content_length,
			private_identity_key_buffer.content));
	if (!private_identity_key) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack private identity key from protobuf.");
	}

	keys = std::make_unique<MasterKeys>(
		*public_signing_key,
		*private_signing_key,
		*public_identity_key,
		*private_identity_key);
}


int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium");
		}
		//create the unspiced master keys
		MasterKeys unspiced_master_keys{};

		//get the public keys
		Buffer public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
		unspiced_master_keys.getSigningKey(public_signing_key);
		Buffer public_identity_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		unspiced_master_keys.getIdentityKey(public_identity_key);

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		std::cout << unspiced_master_keys.public_signing_key.toHex();

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(unspiced_master_keys);
			std::cout << unspiced_master_keys.private_signing_key.toHex();
		}

		printf("\n\nIdentity keys:\n");
		printf("Public:\n");
		std::cout << unspiced_master_keys.public_identity_key.toHex();

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(unspiced_master_keys);
			std::cout << unspiced_master_keys.private_identity_key.toHex();
		}

		//check the exported public keys
		if (public_signing_key != unspiced_master_keys.public_signing_key) {
			throw MolchException(INCORRECT_DATA, "Exported public signing key doesn't match.");
		}
		if (public_identity_key != unspiced_master_keys.public_identity_key) {
			throw MolchException(INCORRECT_DATA, "Exported public identity key doesn't match.");
		}


		//create the spiced master keys
		Buffer seed(";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk");
		exception_on_invalid_buffer(seed);
		MasterKeys spiced_master_keys{seed};
		spiced_master_keys.getSigningKey(public_signing_key);
		spiced_master_keys.getIdentityKey(public_identity_key);

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		std::cout << spiced_master_keys.public_signing_key.toHex();

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(spiced_master_keys);
			std::cout << spiced_master_keys.private_signing_key.toHex();
		}

		printf("\n\nIdentity keys:\n");
		printf("Public:\n");
		std::cout << spiced_master_keys.public_identity_key.toHex();

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(spiced_master_keys);
			std::cout << spiced_master_keys.private_identity_key.toHex();
		}

		//check the exported public keys
		if (public_signing_key != spiced_master_keys.public_signing_key) {
			throw MolchException(INCORRECT_DATA, "Exported public signing key doesn't match.");
		}
		if (public_identity_key != spiced_master_keys.public_identity_key) {
			throw MolchException(INCORRECT_DATA, "Exported public identity key doesn't match.");
		}

		//sign some data
		Buffer data{"This is some data to be signed."};
		printf("Data to be signed.\n");
		printf("%.*s\n", static_cast<int>(data.content_length), reinterpret_cast<char*>(data.content));
		Buffer signed_data{100, 0};
		spiced_master_keys.sign(data, signed_data);
		printf("Signed data:\n");
		std::cout << signed_data.toHex();

		//now check the signature
		Buffer unwrapped_data{100, 0};
		exception_on_invalid_buffer(unwrapped_data);
		unsigned long long unwrapped_data_length;
		int status_int = crypto_sign_open(
				unwrapped_data.content,
				&unwrapped_data_length,
				signed_data.content,
				signed_data.content_length,
				public_signing_key.content);
		if (status_int != 0) {
			throw MolchException(VERIFY_ERROR, "Failed to verify signature.");
		}
		unwrapped_data.content_length = static_cast<size_t>(unwrapped_data_length);

		printf("\nSignature was successfully verified!\n");

		//Test Export to Protobuf-C
		printf("Export to Protobuf-C:\n");

		//export buffers
		auto protobuf_export_public_signing_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_export_private_signing_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_export_public_identity_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_export_private_identity_key = std::unique_ptr<Buffer>(nullptr);
		protobuf_export(
			spiced_master_keys,
			protobuf_export_public_signing_key,
			protobuf_export_private_signing_key,
			protobuf_export_public_identity_key,
			protobuf_export_private_identity_key);

		printf("Public signing key:\n");
		std::cout << protobuf_export_public_signing_key->toHex();
		puts("\n\n");

		printf("Private signing key:\n");
		std::cout << protobuf_export_private_signing_key->toHex();
		puts("\n\n");

		printf("Public identity key:\n");
		std::cout << protobuf_export_public_identity_key->toHex();
		puts("\n\n");

		printf("Private identity key:\n");
		std::cout << protobuf_export_private_identity_key->toHex();
		puts("\n\n");

		//import again
		printf("Import from Protobuf-C:\n");
		auto imported_master_keys = std::unique_ptr<MasterKeys>(nullptr);
		protobuf_import(
			imported_master_keys,
			*protobuf_export_public_signing_key,
			*protobuf_export_private_signing_key,
			*protobuf_export_public_identity_key,
			*protobuf_export_private_identity_key);

		//export again
		auto protobuf_second_export_public_signing_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_second_export_private_signing_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_second_export_public_identity_key = std::unique_ptr<Buffer>(nullptr);
		auto protobuf_second_export_private_identity_key = std::unique_ptr<Buffer>(nullptr);
		protobuf_export(
			*imported_master_keys,
			protobuf_second_export_public_signing_key,
			protobuf_second_export_private_signing_key,
			protobuf_second_export_public_identity_key,
			protobuf_second_export_private_identity_key);

		//now compare
		if (*protobuf_export_public_signing_key != *protobuf_second_export_public_signing_key) {
			throw MolchException(INCORRECT_DATA, "The public signing keys do not match.");
		}
		if (*protobuf_export_private_signing_key != *protobuf_second_export_private_signing_key) {
			throw MolchException(INCORRECT_DATA, "The private signing keys do not match.");
		}
		if (*protobuf_export_public_identity_key != *protobuf_second_export_public_identity_key) {
			throw MolchException(INCORRECT_DATA, "The public identity keys do not match.");
		}
		if (*protobuf_export_private_identity_key != *protobuf_second_export_private_identity_key) {
			throw MolchException(INCORRECT_DATA, "The private identity keys do not match.");
		}

		printf("Successfully exported to Protobuf-C and imported again.");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
