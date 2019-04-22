/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2019 1984not Security GmbH
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

#include "public-prekey-list.hpp"
#include "protobuf-arena.hpp"

#include "sodium-wrappers.hpp"

namespace Molch {
	auto PublicPrekey::isExpired() const noexcept -> bool {
		return this->expiration_date <= now();
	}

	auto PublicPrekey::import(const ProtobufCPublicPrekey& public_prekey_protobuf) noexcept -> result<PublicPrekey> {
		FulfillOrFail(public_prekey_protobuf.public_prekey != nullptr);
		const auto& key_struct{public_prekey_protobuf.public_prekey->key};

		OUTCOME_TRY(public_key, PublicKey::fromSpan({reinterpret_cast<const std::byte*>(key_struct.data), key_struct.len}));

		return PublicPrekey{public_key, seconds{public_prekey_protobuf.expiration_seconds}};
	}

	auto PublicPrekey::exportProtobuf(Arena &arena) const noexcept -> result<ProtobufCPublicPrekey*> {
		auto public_prekey_struct{protobuf_create<ProtobufCPublicPrekey>(arena)};

		auto public_prekey_bytes{arena.allocate<uint8_t>(std::size(this->key))};
		if (public_prekey_bytes == nullptr) {
			return {status_type::ALLOCATION_FAILED, "Failed to allocate bytes for public prekey."};
		}
		OUTCOME_TRY(copyFromTo(this->key, {reinterpret_cast<std::byte*>(public_prekey_bytes), std::size(this->key)}));

		auto public_prekey{arena.allocate<ProtobufCKey>(1)};
		if (public_prekey == nullptr) {
			return {status_type::ALLOCATION_FAILED, "Failed to allocate public prekey."};
		}
		public_prekey->key.data = public_prekey_bytes;
		public_prekey->key.len = std::size(this->key);

		public_prekey_struct->public_prekey = public_prekey;
		public_prekey_struct->expiration_seconds = static_cast<uint64_t>(this->expiration_date.count());

		return public_prekey_struct;
	}

	auto PublicPrekey::operator==(const PublicPrekey& other) const noexcept -> bool {
		if (this->key != other.key) {
			return false;
		}

		return this->expiration_date == other.expiration_date;
	}

	auto PublicPrekeyList::chooseRandom() const noexcept -> result<PublicPrekey> {
		auto non_expired_prekeys{std::vector<PublicPrekey>()};

		const auto current_time{now()};

		std::copy_if(
				std::begin(this->prekeys),
				std::end(this->prekeys),
				std::back_inserter(non_expired_prekeys),
				[](const auto& prekey) {
					return prekey.isExpired();
				});
		if (non_expired_prekeys.empty()) {
			return Error(status_type::OUTDATED, "All prekeys are expired.");
		}

		const auto prekey_index{randombytes_uniform(static_cast<uint32_t>(std::size(non_expired_prekeys)))};
		return non_expired_prekeys[prekey_index];
	}

	auto PublicPrekeyList::exportSignedListSpan(Arena& arena, const MasterKeys& master_keys) const -> result<Buffer> {
		OUTCOME_TRY(protobuf_prekey_list, this->exportProtobuf(arena));

		const auto unsigned_prekey_list_size{molch__protobuf__prekey_list__get_packed_size(protobuf_prekey_list)};
		auto unsigned_prekey_list{arena.allocate<std::byte>(unsigned_prekey_list_size)};
		auto packed_size{molch__protobuf__prekey_list__pack(protobuf_prekey_list, byte_to_uchar(unsigned_prekey_list))};
		if (packed_size != unsigned_prekey_list_size) {
			return {status_type::PROTOBUF_PACK_ERROR, "Failed to pack unsigned prekey list"};
		}

		return master_keys.sign({unsigned_prekey_list, unsigned_prekey_list_size});
	}

	auto PublicPrekeyList::exportSignedList(Arena& arena, const MasterKeys& master_keys) const -> result<span<const std::byte>> {
		OUTCOME_TRY(signed_prekey_list_bytes, exportSignedListSpan(arena, master_keys));

		auto signed_prekey_list_protobuf{protobuf_create<ProtobufCSignedPrekeyList>(arena)};

		signed_prekey_list_protobuf->prekey_list_version = 0;

		signed_prekey_list_protobuf->signed_prekey_list.data = reinterpret_cast<uint8_t*>(std::data(signed_prekey_list_bytes));
		signed_prekey_list_protobuf->signed_prekey_list.len = std::size(signed_prekey_list_bytes);

		// allocate signing key
		auto signing_key{protobuf_create<ProtobufCKey>(arena)};

		// copy the signing key
		const auto& public_signing_key{master_keys.getSigningKey()};
		auto signing_key_data{arena.allocate<std::byte>(std::size(public_signing_key))};
		OUTCOME_TRY(copyFromTo(public_signing_key, {signing_key_data, std::size(public_signing_key)}));

		signing_key->key.data = reinterpret_cast<uint8_t*>(signing_key_data);
		signing_key->key.len = std::size(public_signing_key);

		signed_prekey_list_protobuf->sining_key = signing_key;

		// Pack the result
		const auto packed_signed_prekey_list_size{molch__protobuf__signed_prekey_list__get_packed_size(signed_prekey_list_protobuf)};
		auto packed_signed_prekey_list{arena.allocate<std::byte>(packed_signed_prekey_list_size)};
		auto packed_size{molch__protobuf__signed_prekey_list__pack(signed_prekey_list_protobuf, reinterpret_cast<uint8_t*>(packed_signed_prekey_list))};
		if (packed_size != packed_signed_prekey_list_size) {
			return {status_type::PROTOBUF_PACK_ERROR, "Failed to pack signed prekey list."};
		}

		return {packed_signed_prekey_list, packed_signed_prekey_list_size};
	}

	auto PublicPrekeyList::import(const ProtobufCPrekeyList& prekey_list_protobuf) noexcept -> result<PublicPrekeyList> {
		FulfillOrFail((prekey_list_protobuf.prekeys != nullptr) or (prekey_list_protobuf.n_prekeys == 0));

		auto prekeys{std::vector<PublicPrekey>()};
		prekeys.reserve(prekey_list_protobuf.n_prekeys);

		for (size_t index{0}; index < prekey_list_protobuf.n_prekeys; ++index) {
			const auto protobuf_prekey{prekey_list_protobuf.prekeys[index]};

			OUTCOME_TRY(public_prekey, PublicPrekey::import(*protobuf_prekey));
			prekeys.emplace_back(std::move(public_prekey));
		}

		return PublicPrekeyList{std::move(prekeys)};
	}

	auto PublicPrekeyList::exportProtobuf(Arena &arena) const noexcept -> result<ProtobufCPrekeyList*> {
		auto prekey_list_struct{protobuf_create<ProtobufCPrekeyList>(arena)};

		auto prekey_list{arena.allocate<ProtobufCPublicPrekey*>(std::size(this->prekeys))};
		for (size_t index{0}; index < std::size(this->prekeys); ++index) {
			const auto& prekey{this->prekeys[index]};
			OUTCOME_TRY(exported_prekey, prekey.exportProtobuf(arena));
			prekey_list[index] = exported_prekey;
		}

		prekey_list_struct->n_prekeys = std::size(this->prekeys);
		prekey_list_struct->prekeys = prekey_list;

		return prekey_list_struct;
	}

	auto PublicPrekeyList::operator==(const PublicPrekeyList& other) const noexcept -> bool {
		return this->prekeys == other.prekeys;
	}
}
