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

#include "public-prekey-list.hpp"

#include <algorithm>
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

	auto PublicPrekey::exportProtobuf(Molch::Arena &arena) const noexcept -> result<ProtobufCPublicPrekey*> {
		auto public_prekey_struct{arena.allocate<ProtobufCPublicPrekey>(1)};
		molch__protobuf__public_prekey__init(public_prekey_struct);

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

	auto PublicPrekeyList::exportSignedList(const MasterKeys& master_keys) const -> result<Buffer> {
		auto arena{Arena()};
		OUTCOME_TRY(protobuf_prekey_list, this->exportProtobuf(arena));

		const auto unsigned_prekey_list_size{molch__protobuf__prekey_list__get_packed_size(protobuf_prekey_list)};
		auto unsigned_prekey_list{arena.allocate<std::byte>(unsigned_prekey_list_size)};
		molch__protobuf__prekey_list__pack(protobuf_prekey_list, byte_to_uchar(unsigned_prekey_list));

		return master_keys.sign({unsigned_prekey_list, unsigned_prekey_list_size});
	}

	auto PublicPrekeyList::import(const ProtobufCPrekeyList& prekey_list_protobuf) noexcept -> result<PublicPrekeyList> {
		FulfillOrFail((prekey_list_protobuf.prekeys != nullptr) or (prekey_list_protobuf.n_prekeys == 0));

		auto prekeys{std::vector<PublicPrekey>()};
		prekeys.reserve(prekey_list_protobuf.n_prekeys);

		for (size_t index{0}; index < prekey_list_protobuf.n_prekeys; ++index) {
			const auto protobuf_prekey{prekey_list_protobuf.prekeys[index]};
			if (protobuf_prekey == nullptr) {
				return {status_type::PROTOBUF_MISSING_ERROR, "Missing public prekey in prekey list"};
			}

			OUTCOME_TRY(public_prekey, PublicPrekey::import(*protobuf_prekey));
			prekeys.emplace_back(std::move(public_prekey));
		}

		return PublicPrekeyList{std::move(prekeys)};
	}

	auto PublicPrekeyList::exportProtobuf(Molch::Arena &arena) const noexcept -> result<ProtobufCPrekeyList*> {
		auto prekey_list_struct{arena.allocate<ProtobufCPrekeyList>(1)};
		molch__protobuf__prekey_list__init(prekey_list_struct);

		auto prekey_list{arena.allocate<ProtobufCPublicPrekey*>(std::size(this->prekeys))};
		if (prekey_list == nullptr) {
			return {status_type::ALLOCATION_FAILED, "Failed to allocate pointers to public prekeys."};
		}

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
