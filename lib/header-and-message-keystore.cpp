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
	constexpr int64_t EXPIRATION_TIME{3600 * 24 * 31}; //one month

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
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect header key."};
		}
		this->header_key.set({
				uchar_to_byte(key_bundle.header_key->key.data),
				narrow(key_bundle.header_key->key.len)});

		//import the message key
		if ((key_bundle.message_key == nullptr)
			|| (key_bundle.message_key->key.data == nullptr)
			|| (key_bundle.message_key->key.len != MESSAGE_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has an incorrect message key."};
		}
		this->message_key.set({
				uchar_to_byte(key_bundle.message_key->key.data),
				narrow(key_bundle.message_key->key.len)});

		//import the expiration date
		if (!key_bundle.has_expiration_time) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "KeyBundle has no expiration time."};
		}
		this->expiration_date = gsl::narrow<int64_t>(key_bundle.expiration_time);
	}

	ProtobufCKeyBundle* HeaderAndMessageKey::exportProtobuf(ProtobufPool& pool) const {
		auto key_bundle{pool.allocate<ProtobufCKeyBundle>(1)};
		key_bundle__init(key_bundle);

		//header key
		key_bundle->header_key = pool.allocate<ProtobufCKey>(1);
		key__init(key_bundle->header_key);
		key_bundle->header_key->key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);

		//message key
		key_bundle->message_key = pool.allocate<ProtobufCKey>(1);
		key__init(key_bundle->message_key);
		key_bundle->message_key->key.data = pool.allocate<unsigned char>(MESSAGE_KEY_SIZE);

		//export the header key
		this->header_key.copyTo({uchar_to_byte(key_bundle->header_key->key.data), HEADER_KEY_SIZE});
		key_bundle->header_key->key.len = this->header_key.size();

		//export the message key
		this->message_key.copyTo({uchar_to_byte(key_bundle->message_key->key.data), MESSAGE_KEY_SIZE});
		key_bundle->message_key->key.len = this->message_key.size();


		//set expiration time
		key_bundle->expiration_time = gsl::narrow<uint64_t>(this->expiration_date);
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

	gsl::span<ProtobufCKeyBundle*> HeaderAndMessageKeyStore::exportProtobuf(ProtobufPool& pool) const {
		if (this->keys.size() == 0) {
			return {nullptr};
		}

		//export all buffers
		auto key_bundles{pool.allocate<ProtobufCKeyBundle*>(this->keys.size())};
		size_t index{0};
		for (auto&& key : this->keys) {
			key_bundles[index] = key.exportProtobuf(pool);
			index++;
		}

		return {key_bundles, narrow(this->keys.size())};
	}

	HeaderAndMessageKeyStore::HeaderAndMessageKeyStore(const gsl::span<ProtobufCKeyBundle*> key_bundles) {
		for (const auto& key_bundle : key_bundles) {
			if (key_bundle == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Invalid KeyBundle."};
			}

			this->keys.emplace_back(*key_bundle);
		}
	}

	std::ostream& HeaderAndMessageKeyStore::print(std::ostream& stream) const {
		stream << "KEYSTORE-START-----------------------------------------------------------------\n";
		stream << "Length: " + std::to_string(this->keys.size()) + "\n\n";

		size_t index{0};
		for (const auto& key_bundle : this->keys) {
			stream << "Entry " << index << '\n';
			index++;
			key_bundle.print(stream) << '\n';
		}

		stream << "KEYSTORE-END-------------------------------------------------------------------\n";

		return stream;
	}
}
