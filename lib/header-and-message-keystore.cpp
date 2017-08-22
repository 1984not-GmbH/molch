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
#include "zeroed_malloc.hpp"
#include "molch-exception.hpp"

namespace Molch {
	constexpr int64_t EXPIRATION_TIME = 3600 * 24 * 31; //one month

	void HeaderAndMessageKey::fill(const HeaderKey& header_key, const MessageKey& message_key, const int64_t expiration_date) {
		this->header_key = header_key;
		this->message_key = message_key;
		this->expiration_date = expiration_date;
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key) {
		this->fill(header_key, message_key, time(nullptr) + EXPIRATION_TIME);
	}

	HeaderAndMessageKey::HeaderAndMessageKey(const HeaderKey& header_key, const MessageKey& message_key, const int64_t expiration_date) {
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
			throw Exception(PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect header key.");
		}
		this->header_key.set(key_bundle.header_key->key.data, key_bundle.header_key->key.len);

		//import the message key
		if ((key_bundle.message_key == nullptr)
			|| (key_bundle.message_key->key.data == nullptr)
			|| (key_bundle.message_key->key.len != MESSAGE_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect message key.");
		}
		this->message_key.set(key_bundle.message_key->key.data, key_bundle.message_key->key.len);

		//import the expiration date
		if (!key_bundle.has_expiration_time) {
			throw Exception(PROTOBUF_MISSING_ERROR, "KeyBundle has no expiration time.");
		}
		this->expiration_date = static_cast<int64_t>(key_bundle.expiration_time);
	}

	std::unique_ptr<ProtobufCKeyBundle,KeyBundleDeleter> HeaderAndMessageKey::exportProtobuf() const {
		auto key_bundle = std::unique_ptr<ProtobufCKeyBundle,KeyBundleDeleter>(throwing_zeroed_malloc<ProtobufCKeyBundle>(1));
		key_bundle__init(key_bundle.get());

		//header key
		key_bundle->header_key = throwing_zeroed_malloc<ProtobufCKey>(1);
		key__init(key_bundle->header_key);
		key_bundle->header_key->key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);

		//message key
		key_bundle->message_key = throwing_zeroed_malloc<ProtobufCKey>(1);
		key__init(key_bundle->message_key);
		key_bundle->message_key->key.data = throwing_zeroed_malloc<unsigned char>(MESSAGE_KEY_SIZE);

		//export the header key
		this->header_key.copyTo(key_bundle->header_key->key.data, HEADER_KEY_SIZE);
		key_bundle->header_key->key.len = this->header_key.size();

		//export the message key
		this->message_key.copyTo(key_bundle->message_key->key.data, MESSAGE_KEY_SIZE);
		key_bundle->message_key->key.len = this->message_key.size();


		//set expiration time
		key_bundle->expiration_time = static_cast<uint64_t>(this->expiration_date);
		key_bundle->has_expiration_time = true;

		return key_bundle;
	}

	std::ostream& HeaderAndMessageKey::print(std::ostream& stream) const {
		stream << "Header key:\n";
		this->header_key.printHex(stream) << '\n';
		stream << "Message key:\n";
		this->message_key.printHex(stream) << '\n';
		stream << "Expiration date:\n" << this->expiration_date << '\n';

		return stream;
	}

	void HeaderAndMessageKeyStore::add(const HeaderKey& header_key, const MessageKey& message_key) {
		this->keys.emplace_back(header_key, message_key);
	}

	void HeaderAndMessageKeyStore::exportProtobuf(ProtobufCKeyBundle**& key_bundles, size_t& bundles_size) const {
		if (this->keys.size() == 0) {
			key_bundles = nullptr;
			bundles_size = 0;
			return;
		}

		auto bundles = std::vector<std::unique_ptr<ProtobufCKeyBundle,KeyBundleDeleter>>();
		bundles.reserve(this->keys.size());

		//export all buffers
		for (auto&& key : this->keys) {
			bundles.push_back(key.exportProtobuf());
		}

		//allocate output array
		key_bundles = throwing_zeroed_malloc<ProtobufCKeyBundle*>(this->keys.size());
		size_t index = 0;
		for (auto&& bundle : bundles) {
			key_bundles[index] = bundle.release();
			index++;
		}
		bundles_size = this->keys.size();
	}

	HeaderAndMessageKeyStore::HeaderAndMessageKeyStore(ProtobufCKeyBundle** const & key_bundles, const size_t bundles_size) {
		for (size_t index = 0; index < bundles_size; index++) {
			if (key_bundles[index] == nullptr) {
				throw Exception(PROTOBUF_MISSING_ERROR, "Invalid KeyBundle.");
			}

			this->keys.emplace_back(*key_bundles[index]);
		}
	}

	std::ostream& HeaderAndMessageKeyStore::print(std::ostream& stream) const {
		stream << "KEYSTORE-START-----------------------------------------------------------------\n";
		stream << "Length: " + std::to_string(this->keys.size()) + "\n\n";

		size_t index = 0;
		for (const auto& key_bundle : this->keys) {
			stream << "Entry " << index << '\n';
			index++;
			key_bundle.print(stream) << '\n';
		}

		stream << "KEYSTORE-END-------------------------------------------------------------------\n";

		return stream;
	}
}
