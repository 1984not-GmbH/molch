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
#include "utils.hpp"

using namespace Molch;

static void protobuf_export(
		MasterKeys& keys,
		Buffer& public_signing_key_buffer,
		Buffer& private_signing_key_buffer,
		Buffer& public_identity_key_buffer,
		Buffer& private_identity_key_buffer) {
	ProtobufCKey* public_signing_key;
	ProtobufCKey* private_signing_key;
	ProtobufCKey* public_identity_key;
	ProtobufCKey* private_identity_key;

	Arena pool;
	keys.exportProtobuf(
			pool,
			public_signing_key,
			private_signing_key,
			public_identity_key,
			private_identity_key);

	//copy keys to buffer
	//public signing key
	auto public_signing_key_proto_size{molch__protobuf__key__get_packed_size(public_signing_key)};
	public_signing_key_buffer = Buffer{public_signing_key_proto_size, 0};
	public_signing_key_buffer.setSize(molch__protobuf__key__pack(public_signing_key, byte_to_uchar(public_signing_key_buffer.data())));
	if (!public_signing_key_buffer.contains(public_signing_key_proto_size)) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export public signing key."};
	}

	//private signing key
	auto private_signing_key_proto_size{molch__protobuf__key__get_packed_size(private_signing_key)};
	private_signing_key_buffer = Buffer{private_signing_key_proto_size, 0};
	private_signing_key_buffer.setSize(molch__protobuf__key__pack(private_signing_key, byte_to_uchar(private_signing_key_buffer.data())));
	if (!private_signing_key_buffer.contains(private_signing_key_proto_size)) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export private signing key."};
	}

	//public identity key
	auto public_identity_key_proto_size{molch__protobuf__key__get_packed_size(public_identity_key)};
	public_identity_key_buffer = Buffer{public_identity_key_proto_size, 0};
	public_identity_key_buffer.setSize(molch__protobuf__key__pack(public_identity_key, byte_to_uchar(public_identity_key_buffer.data())));
	if (!public_identity_key_buffer.contains(public_identity_key_proto_size)) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export public identity key."};
	}

	//private identity key
	auto private_identity_key_proto_size{molch__protobuf__key__get_packed_size(private_identity_key)};
	private_identity_key_buffer = Buffer{private_identity_key_proto_size, 0};
	private_identity_key_buffer.setSize(molch__protobuf__key__pack(private_identity_key, byte_to_uchar(private_identity_key_buffer.data())));
	if (!private_identity_key_buffer.contains(private_identity_key_proto_size)) {
		throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export private identity key."};
	}
}


static void protobuf_import(
		Arena& pool,
		std::unique_ptr<MasterKeys>& keys,
		const Buffer& public_signing_key_buffer,
		const Buffer& private_signing_key_buffer,
		const Buffer& public_identity_key_buffer,
		const Buffer& private_identity_key_buffer) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};

	//unpack the protobuf-c buffers
	auto public_signing_key{molch__protobuf__key__unpack(
			&pool_protoc_allocator,
			public_signing_key_buffer.size(),
			byte_to_uchar(public_signing_key_buffer.data()))};
	if (public_signing_key == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack public signing key from protobuf."};
	}
	auto private_signing_key{molch__protobuf__key__unpack(
			&pool_protoc_allocator,
			private_signing_key_buffer.size(),
			byte_to_uchar(private_signing_key_buffer.data()))};
	if (private_signing_key == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack private signing key from protobuf."};
	}
	auto public_identity_key{molch__protobuf__key__unpack(
			&pool_protoc_allocator,
			public_identity_key_buffer.size(),
			byte_to_uchar(public_identity_key_buffer.data()))};
	if (public_identity_key == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack public identity key from protobuf."};
	}
	auto private_identity_key{molch__protobuf__key__unpack(
			&pool_protoc_allocator,
			private_identity_key_buffer.size(),
			byte_to_uchar(private_identity_key_buffer.data()))};
	if (private_identity_key == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack private identity key from protobuf."};
	}

	keys = std::make_unique<MasterKeys>(
		*public_signing_key,
		*private_signing_key,
		*public_identity_key,
		*private_identity_key);
}


int main() {
	try {
		Molch::sodium_init();
		//create the unspiced master keys
		MasterKeys unspiced_master_keys;

		//get the public keys
		PublicSigningKey public_signing_key{unspiced_master_keys.getSigningKey()};
		PublicKey public_identity_key{unspiced_master_keys.getIdentityKey()};

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		unspiced_master_keys.getSigningKey().printHex(std::cout);

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker{unspiced_master_keys};
			unspiced_master_keys.getPrivateSigningKey().printHex(std::cout);
		}

		printf("\n\nIdentity keys:\n");
		printf("Public:\n");
		unspiced_master_keys.getIdentityKey().printHex(std::cout);

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker{unspiced_master_keys};
			unspiced_master_keys.getPrivateIdentityKey().printHex(std::cout);
		}

		//check the exported public keys
		if (public_signing_key != unspiced_master_keys.getSigningKey()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Exported public signing key doesn't match."};
		}
		if (public_identity_key != unspiced_master_keys.getIdentityKey()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Exported public identity key doesn't match."};
		}


		//create the spiced master keys
		Buffer seed{";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk"};
		MasterKeys spiced_master_keys{seed};
		public_signing_key = spiced_master_keys.getSigningKey();
		public_identity_key = spiced_master_keys.getIdentityKey();

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		spiced_master_keys.getSigningKey().printHex(std::cout) << std::endl;

		printf("Private:\n");
		{
			MasterKeys::Unlocker unlocker{spiced_master_keys};
			spiced_master_keys.getPrivateSigningKey().printHex(std::cout) << std::endl;
		}

		printf("\nIdentity keys:\n");
		printf("Public:\n");
		spiced_master_keys.getIdentityKey().printHex(std::cout) << std::endl;

		printf("Private:\n");
		{
			MasterKeys::Unlocker unlocker{spiced_master_keys};
			spiced_master_keys.getPrivateIdentityKey().printHex(std::cout);
		}

		//check the exported public keys
		if (public_signing_key != spiced_master_keys.getSigningKey()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Exported public signing key doesn't match."};
		}
		if (public_identity_key != spiced_master_keys.getIdentityKey()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Exported public identity key doesn't match."};
		}

		//sign some data
		Buffer data{"This is some data to be signed."};
		printf("Data to be signed.\n");
		printf("%.*s\n", static_cast<int>(data.size()), reinterpret_cast<char*>(data.data()));
		Buffer signed_data{100, data.size() + SIGNATURE_SIZE};
		spiced_master_keys.sign(data, signed_data);
		printf("Signed data:\n");
		signed_data.printHex(std::cout);

		//now check the signature
		Buffer unwrapped_data{100, 0};
		unsigned long long unwrapped_data_length;
		auto status{crypto_sign_open(
				byte_to_uchar(unwrapped_data.data()),
				&unwrapped_data_length,
				byte_to_uchar(signed_data.data()),
				signed_data.size(),
				byte_to_uchar(public_signing_key.data()))};
		if (status != 0) {
			throw Molch::Exception{status_type::VERIFY_ERROR, "Failed to verify signature."};
		}
		unwrapped_data.setSize(static_cast<size_t>(unwrapped_data_length));

		printf("\nSignature was successfully verified!\n");

		//Test Export to Protobuf-C
		printf("Export to Protobuf-C:\n");

		//export buffers
		Buffer protobuf_export_public_signing_key;
		Buffer protobuf_export_private_signing_key;
		Buffer protobuf_export_public_identity_key;
		Buffer protobuf_export_private_identity_key;
		protobuf_export(
			spiced_master_keys,
			protobuf_export_public_signing_key,
			protobuf_export_private_signing_key,
			protobuf_export_public_identity_key,
			protobuf_export_private_identity_key);

		printf("Public signing key:\n");
		protobuf_export_public_signing_key.printHex(std::cout) << "\n\n";

		printf("Private signing key:\n");
		protobuf_export_private_signing_key.printHex(std::cout) << "\n\n";

		printf("Public identity key:\n");
		protobuf_export_public_identity_key.printHex(std::cout) << "\n\n";

		printf("Private identity key:\n");
		protobuf_export_private_identity_key.printHex(std::cout) << "\n\n";

		//import again
		printf("Import from Protobuf-C:\n");
		auto imported_master_keys{std::unique_ptr<MasterKeys>(nullptr)};
		Arena pool;
		protobuf_import(
			pool,
			imported_master_keys,
			protobuf_export_public_signing_key,
			protobuf_export_private_signing_key,
			protobuf_export_public_identity_key,
			protobuf_export_private_identity_key);

		//export again
		Buffer protobuf_second_export_public_signing_key;
		Buffer protobuf_second_export_private_signing_key;
		Buffer protobuf_second_export_public_identity_key;
		Buffer protobuf_second_export_private_identity_key;
		protobuf_export(
			*imported_master_keys,
			protobuf_second_export_public_signing_key,
			protobuf_second_export_private_signing_key,
			protobuf_second_export_public_identity_key,
			protobuf_second_export_private_identity_key);

		//now compare
		if (protobuf_export_public_signing_key != protobuf_second_export_public_signing_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "The public signing keys do not match."};
		}
		if (protobuf_export_private_signing_key != protobuf_second_export_private_signing_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "The private signing keys do not match."};
		}
		if (protobuf_export_public_identity_key != protobuf_second_export_public_identity_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "The public identity keys do not match."};
		}
		if (protobuf_export_private_identity_key != protobuf_second_export_private_identity_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "The private identity keys do not match."};
		}

		printf("Successfully exported to Protobuf-C and imported again.");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
