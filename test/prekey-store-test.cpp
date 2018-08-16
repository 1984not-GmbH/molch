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
#include "../lib/destroyers.hpp"
#include "utils.hpp"

using namespace Molch;

static void protobuf_export(
		PrekeyStore& store,
		std::vector<Buffer>& key_buffers,
		std::vector<Buffer>& deprecated_key_buffers) {
	Arena arena;
	TRY_WITH_RESULT(exported_prekeys_result, store.exportProtobuf(arena));
	const auto& exported_prekeys{exported_prekeys_result.value()};

	//export all the keypairs
	key_buffers = std::vector<Buffer>();
	key_buffers.reserve(exported_prekeys.keypairs.size());
	for (const auto& keypair : exported_prekeys.keypairs) {
		auto export_size{molch__protobuf__prekey__get_packed_size(keypair)};
		key_buffers.emplace_back(export_size, 0);

		TRY_VOID(key_buffers.back().setSize(molch__protobuf__prekey__pack(keypair, byte_to_uchar(key_buffers.back().data()))));
	}

	//export all the deprecated keypairs
	deprecated_key_buffers = std::vector<Buffer>();
	deprecated_key_buffers.reserve(exported_prekeys.deprecated_keypairs.size());
	for (const auto& keypair : exported_prekeys.deprecated_keypairs) {
		auto export_size{molch__protobuf__prekey__get_packed_size(keypair)};
		deprecated_key_buffers.emplace_back(export_size, 0);

		TRY_VOID(deprecated_key_buffers.back().setSize(molch__protobuf__prekey__pack(keypair, byte_to_uchar(deprecated_key_buffers.back().data()))));
	}
}

static PrekeyStore protobuf_import(
		Arena& pool,
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
	TRY_WITH_RESULT(prekey_store, PrekeyStore::import(
			span<ProtobufCPrekey*>{keypairs_array.get(), keypair_buffers.size()},
			span<ProtobufCPrekey*>{deprecated_keypairs_array.get(), deprecated_keypair_buffers.size()}));
	return std::move(prekey_store.value());
}

static void protobuf_no_deprecated_keys() {
	printf("Testing im-/export of prekey store without deprecated keys.\n");
	TRY_WITH_RESULT(store_result, PrekeyStore::create());
	auto& store{store_result.value()};

	//export it
	Arena arena;
	TRY_WITH_RESULT(exported_result, store.exportProtobuf(arena));
	const auto& exported{exported_result.value()};

	if (not exported.deprecated_keypairs.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported deprecated prekeys are not empty."};
	}

	//import it
	TRY_WITH_RESULT(imported_store, PrekeyStore::import(exported.keypairs, exported.deprecated_keypairs));
	store = std::move(imported_store.value());

	printf("Successful.\n");
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		TRY_WITH_RESULT(store_result, PrekeyStore::create());
		auto& store{store_result.value()};
		TRY_WITH_RESULT(prekey_list_result, store.list());
		const auto& prekey_list{prekey_list_result.value()};
		printf("Prekey list:\n");
		std::cout << prekey_list << std::endl;

		//compare the public keys with the ones in the prekey store
		for (size_t i{0}; i < PREKEY_AMOUNT; i++) {
			TRY_WITH_RESULT(comparison, prekey_list.compareToRawPartial(PUBLIC_KEY_SIZE * i, {store.prekeys()[i].publicKey().data(), store.prekeys()[i].publicKey().size()}, 0, PUBLIC_KEY_SIZE));
			if (!comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Key list doesn't match the prekey store."};
			}
		}
		printf("Prekey list matches the prekey store!\n");

		//get a private key
		const size_t prekey_index{10};
		PublicKey public_prekey{store.prekeys()[prekey_index].publicKey()};

		TRY_WITH_RESULT(private_prekey1_result, store.getPrekey(public_prekey));
		const auto& private_prekey1{private_prekey1_result.value()};
		printf("Get a Prekey:\n");
		printf("Public key:\n");
		std::cout << public_prekey;
		printf("Private key:\n");
		std::cout << private_prekey1 << std::endl;

		if (store.deprecatedPrekeys().empty()) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to deprecate requested key."};
		}

		if ((public_prekey != store.deprecatedPrekeys()[0].publicKey())
				|| (private_prekey1 != store.deprecatedPrekeys()[0].privateKey())) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Deprecated key is incorrect."};
		}

		if (store.prekeys()[prekey_index].publicKey() == public_prekey) {
			throw Molch::Exception{status_type::KEYGENERATION_FAILED, "Failed to generate new key for deprecated one."};
		}
		printf("Successfully deprecated requested key!\n");

		//check if the prekey can be obtained from the deprecated keys
		TRY_WITH_RESULT(private_prekey2_result, store.getPrekey(public_prekey));
		const auto& private_prekey2{private_prekey2_result.value()};

		if (private_prekey1 != private_prekey2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Prekey from the deprecated area didn't match."};
		}
		printf("Successfully got prekey from the deprecated area!\n");

		//try to get a nonexistent key
		randombytes_buf(public_prekey);
		const auto nonexistent_prekey = store.getPrekey(public_prekey);
		if (nonexistent_prekey.has_value()) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Didn't complain about invalid public key."};
		}
		printf("Detected invalid public prekey!\n");

		//Protobuf-C export
		printf("Protobuf-C export\n");
		std::vector<Buffer> protobuf_export_prekeys_buffers;
		std::vector<Buffer> protobuf_export_deprecated_prekeys_buffers;
		protobuf_export(
			store,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers);

		printf("Prekeys:\n");
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_prekeys_buffers.size(); i++) {
			std::cout << protobuf_export_prekeys_buffers[i] << ",\n";
		}
		puts("]\n\n");

		printf("Deprecated Prekeys:\n");
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_deprecated_prekeys_buffers.size(); i++) {
			std::cout << protobuf_export_deprecated_prekeys_buffers[i] << ",\n";
		}
		puts("]\n\n");

		printf("Import from Protobuf-C\n");
		Arena pool;
		auto imported_store{protobuf_import(
			pool,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers)};

		printf("Protobuf-C export again\n");
		std::vector<Buffer> protobuf_second_export_prekeys_buffers;
		std::vector<Buffer> protobuf_second_export_deprecated_prekeys_buffers;
		protobuf_export(
			imported_store,
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
		public_prekey = imported_store.prekeys()[PREKEY_AMOUNT-1].publicKey();

		TRY_VOID(imported_store.timeshiftForTestingOnly(PREKEY_AMOUNT - 1, -12_months));

		TRY_VOID(imported_store.rotate());

		if (imported_store.deprecatedPrekeys().back().publicKey() != public_prekey) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to deprecate outdated key."};
		}
		printf("Successfully deprecated outdated key!\n");

		//test the automatic removal of old deprecated keys!
		public_prekey = imported_store.deprecatedPrekeys()[1].publicKey();

		imported_store.timeshiftDeprecatedForTestingOnly(1, -1_days);

		TRY_VOID(imported_store.rotate());

		if (imported_store.deprecatedPrekeys().size() != 1) {
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
