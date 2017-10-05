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

#include "constants.h"
#include "header-and-message-keystore.hpp"
#include "molch-exception.hpp"
#include "gsl.hpp"

namespace Molch {
	constexpr auto expiration_time{1_months};

	void HeaderAndMessageKey::fill(const HeaderKey& header_key, const MessageKey& message_key, const seconds expiration_date) {
		this->header_key = header_key;
		this->message_key = message_key;
		this->expiration_date = expiration_date;
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key) {
		this->fill(header_key, message_key, now() + expiration_time);
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key, const seconds expiration_date) {
		this->fill(header_key, message_key, expiration_date);
	}

	HeaderAndMessageKey& HeaderAndMessageKey::copy(const HeaderAndMessageKey& node) {
		this->fill(node.header_key, node.message_key, node.expiration_date);

		return *this;
	}

	HeaderAndMessageKey& HeaderAndMessageKey::move(HeaderAndMessageKey&& node) {
		this->fill(node.header_key, node.message_key, node.expiration_date);

		return *this;
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const HeaderAndMessageKey& node) {
		this->copy(node);
	}

	HeaderAndMessageKey::HeaderAndMessageKey(HeaderAndMessageKey&& node) {
		this->move(std::move(node));
	}

	HeaderAndMessageKey& HeaderAndMessageKey::operator=(const HeaderAndMessageKey& node) {
		return this->copy(node);
	}

	HeaderAndMessageKey& HeaderAndMessageKey::operator=(HeaderAndMessageKey&& node) {
		return this->move(std::move(node));
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const ProtobufCKeyBundle& key_bundle) {
		//import the header key
		if ((key_bundle.header_key == nullptr)
			|| (key_bundle.header_key->key.data == nullptr)
			|| (key_bundle.header_key->key.len != HEADER_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect header key."};
		}
		this->header_key = HeaderKey{*key_bundle.header_key};

		//import the message key
		if ((key_bundle.message_key == nullptr)
			|| (key_bundle.message_key->key.data == nullptr)
			|| (key_bundle.message_key->key.len != MESSAGE_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect message key."};
		}
		this->message_key = MessageKey{*key_bundle.message_key};

		//import the expiration date
		if (!key_bundle.has_expiration_time) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has no expiration time."};
		}
		this->expiration_date = seconds{key_bundle.expiration_time};
	}

	const MessageKey& HeaderAndMessageKey::messageKey() const {
		return this->message_key;
	}

	const HeaderKey& HeaderAndMessageKey::headerKey() const {
		return this->header_key;
	}
	seconds HeaderAndMessageKey::expirationDate() const {
		return this->expiration_date;
	}

	ProtobufCKeyBundle* HeaderAndMessageKey::exportProtobuf(ProtobufPool& pool) const {
		auto key_bundle{pool.allocate<ProtobufCKeyBundle>(1)};
		key_bundle__init(key_bundle);

		//export the keys
		key_bundle->header_key = this->header_key.exportProtobuf(pool);
		key_bundle->message_key = this->message_key.exportProtobuf(pool);

		//set expiration time
		key_bundle->expiration_time = gsl::narrow<uint64_t>(this->expiration_date.count());
		key_bundle->has_expiration_time = true;

		return key_bundle;
	}

	std::ostream& HeaderAndMessageKey::print(std::ostream& stream) const {
		stream << "Header key:\n";
		this->header_key.printHex(stream) << '\n';
		stream << "Message key:\n";
		this->message_key.printHex(stream) << '\n';
		stream << "Expiration date:\n" << this->expiration_date.count() << 's' << '\n';

		return stream;
	}

	void HeaderAndMessageKeyStore::add(const HeaderAndMessageKeyStore& keystore) {
		for (const auto key_bundle : keystore.keys()) {
			this->add(key_bundle);
		}
	}

	void HeaderAndMessageKeyStore::add(const HeaderKey& header_key, const MessageKey& message_key) {
		HeaderAndMessageKey key_bundle{header_key, message_key};
		this->add(key_bundle);
	}

	void HeaderAndMessageKeyStore::add(const HeaderAndMessageKey& key) {
		//common shortpath
		if (this->key_storage.empty() || (this->key_storage.back().expirationDate() <= key.expirationDate())) {
			this->key_storage.push_back(key);
			return;
		}

		//find the position to insert at
		auto bound{std::upper_bound(
				std::cbegin(this->key_storage),
				std::cend(this->key_storage),
				key,
				//comparator
				[](const HeaderAndMessageKey& a, const HeaderAndMessageKey& b) {
					if (a.expirationDate() < b.expirationDate()) {
						return true;
					}

					return false;
				})};

		this->key_storage.insert(bound, key);
	}

	void HeaderAndMessageKeyStore::remove(size_t index) {
		this->key_storage.erase(std::begin(this->key_storage) + gsl::narrow<ptrdiff_t>(index));
	}

	void HeaderAndMessageKeyStore::clear() {
		this->key_storage.clear();
	}

	const std::vector<HeaderAndMessageKey,SodiumAllocator<HeaderAndMessageKey>>& HeaderAndMessageKeyStore::keys() const {
		return this->key_storage;
	}

	span<ProtobufCKeyBundle*> HeaderAndMessageKeyStore::exportProtobuf(ProtobufPool& pool) const {
		if (this->key_storage.size() == 0) {
			return {nullptr};
		}

		//export all buffers
		auto key_bundles{pool.allocate<ProtobufCKeyBundle*>(this->key_storage.size())};
		size_t index{0};
		for (const auto& key : this->key_storage) {
			key_bundles[index] = key.exportProtobuf(pool);
			index++;
		}

		return {key_bundles, this->key_storage.size()};
	}

	HeaderAndMessageKeyStore::HeaderAndMessageKeyStore(const span<ProtobufCKeyBundle*> key_bundles) {
		for (const auto& key_bundle : key_bundles) {
			if (key_bundle == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Invalid KeyBundle."};
			}

			this->key_storage.emplace_back(*key_bundle);
		}
	}

	std::ostream& HeaderAndMessageKeyStore::print(std::ostream& stream) const {
		stream << "KEYSTORE-START-----------------------------------------------------------------\n";
		stream << "Length: " + std::to_string(this->key_storage.size()) + "\n\n";

		size_t index{0};
		for (const auto& key_bundle : this->key_storage) {
			stream << "Entry " << index << '\n';
			index++;
			key_bundle.print(stream) << '\n';
		}

		stream << "KEYSTORE-END-------------------------------------------------------------------\n";

		return stream;
	}
}
