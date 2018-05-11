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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <iostream>
#include <exception>

#include "../lib/prekey-store.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"

using namespace Molch;

static void protobuf_export(
		PrekeyStore& store,
		std::vector<Buffer>& key_buffers,
		std::vector<Buffer>& deprecated_key_buffers) {
	Arena pool;
	span<ProtobufCPrekey*> exported_keypairs;
	span<ProtobufCPrekey*> exported_deprecated_keypairs;
	store.exportProtobuf(
		pool,
		exported_keypairs,
		exported_deprecated_keypairs);

	//export all the keypairs
	key_buffers = std::vector<Buffer>();
	key_buffers.reserve(exported_keypairs.size());
	for (const auto& keypair : exported_keypairs) {
		auto export_size{molch__protobuf__prekey__get_packed_size(keypair)};
		key_buffers.emplace_back(export_size, 0);

		key_buffers.back().setSize(molch__protobuf__prekey__pack(keypair, byte_to_uchar(key_buffers.back().data())));
	}

	//export all the deprecated keypairs
	deprecated_key_buffers = std::vector<Buffer>();
	deprecated_key_buffers.reserve(exported_deprecated_keypairs.size());
	for (const auto& keypair : exported_deprecated_keypairs) {
		auto export_size{molch__protobuf__prekey__get_packed_size(keypair)};
		deprecated_key_buffers.emplace_back(export_size, 0);

		deprecated_key_buffers.back().setSize(molch__protobuf__prekey__pack(keypair, byte_to_uchar(deprecated_key_buffers.back().data())));
	}
}

static void protobuf_import(
		Arena& pool,
		std::unique_ptr<PrekeyStore>& store,
		const std::vector<Buffer>& keypair_buffers,
		const std::vector<Buffer>& deprecated_keypair_buffers) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//parse the normal prekey protobufs
	auto keypairs_array{std::unique_ptr<ProtobufCPrekey*[]>(new ProtobufCPrekey*[keypair_buffers.size()])};
	size_t index{0};
	for (const auto& keypair_buffer : keypair_buffers) {
		keypairs_array[index] = molch__protobuf__prekey__unpack(
				&pool_protoc_allocator,
				keypair_buffer.size(),
				byte_to_uchar(keypair_buffer.data()));
		if (keypairs_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack prekey from protobuf."};
		}

		index++;
	}

	//parse the deprecated prekey protobufs
	auto deprecated_keypairs_array{std::unique_ptr<ProtobufCPrekey*[]>(new ProtobufCPrekey*[deprecated_keypair_buffers.size()])};
	index = 0;
	for (const auto& keypair_buffer : deprecated_keypair_buffers) {
		deprecated_keypairs_array[index] = molch__protobuf__prekey__unpack(
				&pool_protoc_allocator,
				keypair_buffer.size(),
				byte_to_uchar(keypair_buffer.data()));
		if (deprecated_keypairs_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack deprecated prekey from protobuf."};
		}

		index++;
	}

	//now do the import
	store = std::make_unique<PrekeyStore>(
			span<ProtobufCPrekey*>{keypairs_array.get(), keypair_buffers.size()},
			span<ProtobufCPrekey*>{deprecated_keypairs_array.get(), deprecated_keypair_buffers.size()});
}

static void protobuf_no_deprecated_keys() {
	printf("Testing im-/export of prekey store without deprecated keys.\n");
	PrekeyStore store;

	//export it
	Arena pool;
	span<ProtobufCPrekey*> exported;
	span<ProtobufCPrekey*> deprecated;
	store.exportProtobuf(pool, exported, deprecated);

	if (!deprecated.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported deprecated prekeys are not empty."};
	}

	//import it
	store = PrekeyStore(exported, deprecated);

	printf("Successful.\n");
}

int main() {
	try {
		Molch::sodium_init();

		auto store{std::make_unique<PrekeyStore>()};
		Buffer prekey_list{PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE};
		store->list(prekey_list);
		printf("Prekey list:\n");
		prekey_list.printHex(std::cout) << std::endl;

		//compare the public keys with the ones in the prekey store
		for (size_t i{0}; i < PREKEY_AMOUNT; i++) {
			if (prekey_list.compareToRawPartial(PUBLIC_KEY_SIZE * i, {store->prekeys()[i].publicKey().data(), store->prekeys()[i].publicKey().size()}, 0, PUBLIC_KEY_SIZE) != 0) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Key list doesn't match the prekey store."};
			}
		}
		printf("Prekey list matches the prekey store!\n");

		//get a private key
		const size_t prekey_index{10};
		PublicKey public_prekey{store->prekeys()[prekey_index].publicKey()};

		PrivateKey private_prekey1;
		store->getPrekey(public_prekey, private_prekey1);
		printf("Get a Prekey:\n");
		printf("Public key:\n");
		public_prekey.printHex(std::cout);
		printf("Private key:\n");
		private_prekey1.printHex(std::cout) << std::endl;

		if (store->deprecatedPrekeys().empty()) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to deprecate requested key."};
		}

		if ((public_prekey != store->deprecatedPrekeys()[0].publicKey())
				|| (private_prekey1 != store->deprecatedPrekeys()[0].privateKey())) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Deprecated key is incorrect."};
		}

		if (store->prekeys()[prekey_index].publicKey() == public_prekey) {
			throw Molch::Exception{status_type::KEYGENERATION_FAILED, "Failed to generate new key for deprecated one."};
		}
		printf("Successfully deprecated requested key!\n");

		//check if the prekey can be obtained from the deprecated keys
		PrivateKey private_prekey2;
		store->getPrekey(public_prekey, private_prekey2);

		if (private_prekey1 != private_prekey2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Prekey from the deprecated area didn't match."};
		}
		printf("Successfully got prekey from the deprecated area!\n");

		//try to get a nonexistent key
		public_prekey.fillRandom();
		auto found{true};
		try {
			store->getPrekey(public_prekey, private_prekey1);
		} catch (const Molch::Exception&) {
			found = false;
		}
		if (found) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Didn't complain about invalid public key."};
		}
		printf("Detected invalid public prekey!\n");

		//Protobuf-C export
		printf("Protobuf-C export\n");
		std::vector<Buffer> protobuf_export_prekeys_buffers;
		std::vector<Buffer> protobuf_export_deprecated_prekeys_buffers;
		protobuf_export(
			*store,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers);

		printf("Prekeys:\n");
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_prekeys_buffers.size(); i++) {
			protobuf_export_prekeys_buffers[i].printHex(std::cout) << ",\n";
		}
		puts("]\n\n");

		printf("Deprecated Prekeys:\n");
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_deprecated_prekeys_buffers.size(); i++) {
			protobuf_export_deprecated_prekeys_buffers[i].printHex(std::cout) << ",\n";
		}
		puts("]\n\n");

		store.reset();

		printf("Import from Protobuf-C\n");
		Arena pool;
		protobuf_import(
			pool,
			store,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers);

		printf("Protobuf-C export again\n");
		std::vector<Buffer> protobuf_second_export_prekeys_buffers;
		std::vector<Buffer> protobuf_second_export_deprecated_prekeys_buffers;
		protobuf_export(
			*store,
			protobuf_second_export_prekeys_buffers,
			protobuf_second_export_deprecated_prekeys_buffers);

		//compare both prekey lists
		printf("Compare normal prekeys\n");
		if (protobuf_export_prekeys_buffers.size() != protobuf_second_export_prekeys_buffers.size()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both prekey exports contain different amounts of keys."};
		}
		for (size_t i{0}; i < protobuf_export_prekeys_buffers.size(); i++) {
			if (protobuf_export_prekeys_buffers[i] != protobuf_second_export_prekeys_buffers[i]) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "First and second prekey export are not identical."};
			}
		}

		//compare both deprecated prekey lists
		printf("Compare deprecated prekeys\n");
		if (protobuf_export_deprecated_prekeys_buffers.size() != protobuf_second_export_deprecated_prekeys_buffers.size()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both depcated prekey exports contain different amounts of keys."};
		}
		for (size_t i{0}; i < protobuf_export_deprecated_prekeys_buffers.size(); i++) {
			if (protobuf_export_deprecated_prekeys_buffers[i] != protobuf_second_export_deprecated_prekeys_buffers[i]) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "First and second deprecated prekey export are not identical."};
			}
		}

		//test the automatic deprecation of old keys
		public_prekey = store->prekeys()[PREKEY_AMOUNT-1].publicKey();

		store->timeshiftForTestingOnly(PREKEY_AMOUNT - 1, -12_months);

		store->rotate();

		if (store->deprecatedPrekeys().back().publicKey() != public_prekey) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to deprecate outdated key."};
		}
		printf("Successfully deprecated outdated key!\n");

		//test the automatic removal of old deprecated keys!
		public_prekey = store->deprecatedPrekeys()[1].publicKey();

		store->timeshiftDeprecatedForTestingOnly(1, -1_days);

		store->rotate();

		if (store->deprecatedPrekeys().size() != 1) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to remove outdated key."};
		}
		printf("Successfully removed outdated deprecated key!\n");

		protobuf_no_deprecated_keys();
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
