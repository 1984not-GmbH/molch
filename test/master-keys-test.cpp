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
#include "utils.hpp"

using namespace Molch;

static void protobuf_export(
		MasterKeys& keys,
		Buffer& public_signing_key_buffer,
		Buffer& private_signing_key_buffer,
		Buffer& public_identity_key_buffer,
		Buffer& private_identity_key_buffer) {
	std::unique_ptr<ProtobufCKey,KeyDeleter> public_signing_key;
	std::unique_ptr<ProtobufCKey,KeyDeleter> private_signing_key;
	std::unique_ptr<ProtobufCKey,KeyDeleter> public_identity_key;
	std::unique_ptr<ProtobufCKey,KeyDeleter> private_identity_key;

	keys.exportProtobuf(
				public_signing_key,
				private_signing_key,
				public_identity_key,
				private_identity_key);

	//copy keys to buffer
	//public signing key
	size_t public_signing_key_proto_size = key__get_packed_size(public_signing_key.get());
	public_signing_key_buffer = Buffer(public_signing_key_proto_size, 0);
	public_signing_key_buffer.size = key__pack(public_signing_key.get(), public_signing_key_buffer.content);
	if (!public_signing_key_buffer.contains(public_signing_key_proto_size)) {
		throw Molch::Exception(EXPORT_ERROR, "Failed to export public signing key.");
	}

	//private signing key
	size_t private_signing_key_proto_size = key__get_packed_size(private_signing_key.get());
	private_signing_key_buffer = Buffer(private_signing_key_proto_size, 0);
	private_signing_key_buffer.size = key__pack(private_signing_key.get(), private_signing_key_buffer.content);
	if (!private_signing_key_buffer.contains(private_signing_key_proto_size)) {
		throw Molch::Exception(EXPORT_ERROR, "Failed to export private signing key.");
	}

	//public identity key
	size_t public_identity_key_proto_size = key__get_packed_size(public_identity_key.get());
	public_identity_key_buffer = Buffer(public_identity_key_proto_size, 0);
	public_identity_key_buffer.size = key__pack(public_identity_key.get(), public_identity_key_buffer.content);
	if (!public_identity_key_buffer.contains(public_identity_key_proto_size)) {
		throw Molch::Exception(EXPORT_ERROR, "Failed to export public identity key.");
	}

	//private identity key
	size_t private_identity_key_proto_size = key__get_packed_size(private_identity_key.get());
	private_identity_key_buffer = Buffer(private_identity_key_proto_size, 0);
	private_identity_key_buffer.size = key__pack(private_identity_key.get(), private_identity_key_buffer.content);
	if (!private_identity_key_buffer.contains(private_identity_key_proto_size)) {
		throw Molch::Exception(EXPORT_ERROR, "Failed to export private identity key.");
	}
}


static void protobuf_import(
		std::unique_ptr<MasterKeys>& keys,
		const Buffer& public_signing_key_buffer,
		const Buffer& private_signing_key_buffer,
		const Buffer& public_identity_key_buffer,
		const Buffer& private_identity_key_buffer) {
	//unpack the protobuf-c buffers
	auto public_signing_key = std::unique_ptr<ProtobufCKey,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			public_signing_key_buffer.size,
			public_signing_key_buffer.content));
	if (!public_signing_key) {
		throw Molch::Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack public signing key from protobuf.");
	}
	auto private_signing_key = std::unique_ptr<ProtobufCKey,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			private_signing_key_buffer.size,
			private_signing_key_buffer.content));
	if (!private_signing_key) {
		throw Molch::Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack private signing key from protobuf.");
	}
	auto public_identity_key = std::unique_ptr<ProtobufCKey,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			public_identity_key_buffer.size,
			public_identity_key_buffer.content));
	if (!public_identity_key) {
		throw Molch::Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack public identity key from protobuf.");
	}
	auto private_identity_key = std::unique_ptr<ProtobufCKey,KeyDeleter>(
		key__unpack(
			&protobuf_c_allocators,
			private_identity_key_buffer.size,
			private_identity_key_buffer.content));
	if (!private_identity_key) {
		throw Molch::Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack private identity key from protobuf.");
	}

	keys = std::make_unique<MasterKeys>(
		*public_signing_key,
		*private_signing_key,
		*public_identity_key,
		*private_identity_key);
}


int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception(INIT_ERROR, "Failed to initialize libsodium");
		}
		//create the unspiced master keys
		MasterKeys unspiced_master_keys{};

		//get the public keys
		PublicSigningKey public_signing_key;
		unspiced_master_keys.getSigningKey(public_signing_key);
		PublicKey public_identity_key;
		unspiced_master_keys.getIdentityKey(public_identity_key);

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		unspiced_master_keys.public_signing_key.printHex(std::cout);

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(unspiced_master_keys);
			unspiced_master_keys.private_signing_key->printHex(std::cout);
		}

		printf("\n\nIdentity keys:\n");
		printf("Public:\n");
		unspiced_master_keys.public_identity_key.printHex(std::cout);

		printf("\nPrivate:\n");
		{
			MasterKeys::Unlocker unlocker(unspiced_master_keys);
			unspiced_master_keys.private_identity_key->printHex(std::cout);
		}

		//check the exported public keys
		if (public_signing_key != unspiced_master_keys.public_signing_key) {
			throw Molch::Exception(INCORRECT_DATA, "Exported public signing key doesn't match.");
		}
		if (public_identity_key != unspiced_master_keys.public_identity_key) {
			throw Molch::Exception(INCORRECT_DATA, "Exported public identity key doesn't match.");
		}


		//create the spiced master keys
		Buffer seed(";a;awoeih]]pquw4t[spdif\\aslkjdf;'ihdg#)%!@))%)#)(*)@)#)h;kuhe[orih;o's':ke';sa'd;kfa';;.calijv;a/orq930u[sd9f0u;09[02;oasijd;adk");
		MasterKeys spiced_master_keys{seed};
		spiced_master_keys.getSigningKey(public_signing_key);
		spiced_master_keys.getIdentityKey(public_identity_key);

		//print the keys
		printf("Signing keypair:\n");
		printf("Public:\n");
		spiced_master_keys.public_signing_key.printHex(std::cout) << std::endl;

		printf("Private:\n");
		{
			MasterKeys::Unlocker unlocker(spiced_master_keys);
			spiced_master_keys.private_signing_key->printHex(std::cout) << std::endl;
		}

		printf("\nIdentity keys:\n");
		printf("Public:\n");
		spiced_master_keys.public_identity_key.printHex(std::cout) << std::endl;

		printf("Private:\n");
		{
			MasterKeys::Unlocker unlocker(spiced_master_keys);
			spiced_master_keys.private_identity_key->printHex(std::cout);
		}

		//check the exported public keys
		if (public_signing_key != spiced_master_keys.public_signing_key) {
			throw Molch::Exception(INCORRECT_DATA, "Exported public signing key doesn't match.");
		}
		if (public_identity_key != spiced_master_keys.public_identity_key) {
			throw Molch::Exception(INCORRECT_DATA, "Exported public identity key doesn't match.");
		}

		//sign some data
		Buffer data{"This is some data to be signed."};
		printf("Data to be signed.\n");
		printf("%.*s\n", static_cast<int>(data.size), reinterpret_cast<char*>(data.content));
		Buffer signed_data{100, 0};
		spiced_master_keys.sign(data, signed_data);
		printf("Signed data:\n");
		signed_data.printHex(std::cout);

		//now check the signature
		Buffer unwrapped_data{100, 0};
		unsigned long long unwrapped_data_length;
		int status_int = crypto_sign_open(
				unwrapped_data.content,
				&unwrapped_data_length,
				signed_data.content,
				signed_data.size,
				public_signing_key.data());
		if (status_int != 0) {
			throw Molch::Exception(VERIFY_ERROR, "Failed to verify signature.");
		}
		unwrapped_data.size = static_cast<size_t>(unwrapped_data_length);

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
		auto imported_master_keys = std::unique_ptr<MasterKeys>(nullptr);
		protobuf_import(
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
			throw Molch::Exception(INCORRECT_DATA, "The public signing keys do not match.");
		}
		if (protobuf_export_private_signing_key != protobuf_second_export_private_signing_key) {
			throw Molch::Exception(INCORRECT_DATA, "The private signing keys do not match.");
		}
		if (protobuf_export_public_identity_key != protobuf_second_export_public_identity_key) {
			throw Molch::Exception(INCORRECT_DATA, "The public identity keys do not match.");
		}
		if (protobuf_export_private_identity_key != protobuf_second_export_private_identity_key) {
			throw Molch::Exception(INCORRECT_DATA, "The private identity keys do not match.");
		}

		printf("Successfully exported to Protobuf-C and imported again.");
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
