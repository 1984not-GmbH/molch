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

#include <sodium.h>
#include <algorithm>
#include <climits>
#include <iterator>

#include "prekey-store.hpp"
#include "molch-exception.hpp"

namespace Molch {
	constexpr int64_t PREKEY_EXPIRATION_TIME = 3600 * 24 * 31; //one month
	constexpr int64_t DEPRECATED_PREKEY_EXPIRATION_TIME = 3600; //one hour

	void Prekey::fill(const PublicKey& public_key, const PrivateKey& private_key, const int64_t expiration_date) {
		this->expiration_date = expiration_date;
		this->public_key = public_key;
		this->private_key = private_key;
	}

	Prekey::Prekey(const PublicKey& public_key, const PrivateKey& private_key, int64_t expiration_date) {
		this->fill(public_key, private_key, expiration_date);
	}

	Prekey& Prekey::copy(const Prekey& node) {
		this->fill(node.public_key, node.private_key, node.expiration_date);

		return *this;
	}

	Prekey& Prekey::move(Prekey&& node) {
		return this->copy(node);
	}

	Prekey::Prekey(const Prekey& node) {
		this->copy(node);
	}

	Prekey::Prekey(Prekey&& node) {
		this->move(std::move(node));
	}

	Prekey& Prekey::operator=(const Prekey& node) {
		return this->copy(node);
	}

	Prekey& Prekey::operator=(Prekey&& node) {
		return this->move(std::move(node));
	}

	Prekey::Prekey(const ProtobufCPrekey& keypair) {
		//import private key
		if ((keypair.private_key == nullptr)
				|| (keypair.private_key->key.len != PRIVATE_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a private key.");
		}
		this->private_key.set(keypair.private_key->key.data, keypair.private_key->key.len);

		//import public key
		if (keypair.public_key == nullptr) {
			//public key is missing -> derive it from the private key
			if (crypto_scalarmult_base(this->public_key.data(), this->private_key.data()) != 0) {
				throw Exception(KEYDERIVATION_FAILED, "Failed to derive public prekey from private one.");
			}
			this->public_key.empty = false;
		} else if (keypair.public_key->key.len != PUBLIC_KEY_SIZE) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a public key.");
		} else {
			this->public_key.set(keypair.public_key->key.data, keypair.public_key->key.len);
		}

		//import expiration_date
		if (!keypair.has_expiration_time) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing an expiration time.");
		}
		this->expiration_date = static_cast<int64_t>(keypair.expiration_time);
	}

	std::unique_ptr<ProtobufCPrekey,PrekeyDeleter> Prekey::exportProtobuf() const {
		auto prekey = std::unique_ptr<ProtobufCPrekey,PrekeyDeleter>(throwing_zeroed_malloc<ProtobufCPrekey>(1));
		prekey__init(prekey.get());

		//export the private key
		prekey->private_key = throwing_zeroed_malloc<ProtobufCKey>(1);
		key__init(prekey->private_key);
		prekey->private_key->key.data = throwing_zeroed_malloc<uint8_t>(PRIVATE_KEY_SIZE);
		prekey->private_key->key.len = PRIVATE_KEY_SIZE;
		this->private_key.copyTo(prekey->private_key->key.data, prekey->private_key->key.len);

		//export the public key
		prekey->public_key = throwing_zeroed_malloc<ProtobufCKey>(1);
		key__init(prekey->public_key);
		prekey->public_key->key.data = throwing_zeroed_malloc<uint8_t>(PUBLIC_KEY_SIZE);
		prekey->public_key->key.len = PUBLIC_KEY_SIZE;
		this->public_key.copyTo(prekey->public_key->key.data, prekey->public_key->key.len);

		//export the expiration date
		prekey->expiration_time = static_cast<uint64_t>(this->expiration_date);
		prekey->has_expiration_time = true;

		return prekey;
	}

	void Prekey::generate() {
		int status = crypto_box_keypair(
			this->public_key.data(),
			this->private_key.data());
		if (status != 0) {
			throw Exception(KEYGENERATION_FAILED, "Failed to generate prekey pair.");
		}
		this->public_key.empty = false;
		this->private_key.empty = false;
		this->expiration_date = time(nullptr) + PREKEY_EXPIRATION_TIME;
	}

	std::ostream& Prekey::print(std::ostream& stream) const {
		stream << "Expiration Date = " << std::to_string(this->expiration_date) << '\n';
		stream << "Public Prekey:\n";
		this->public_key.printHex(stream) << '\n';
		stream << "Private Prekey:\n";
		this->private_key.printHex(stream) << '\n';

		return stream;
	}

	void PrekeyStore::init() {
		this->prekeys = std::unique_ptr<std::array<Prekey,PREKEY_AMOUNT>,SodiumDeleter<std::array<Prekey,PREKEY_AMOUNT>>>(throwing_sodium_malloc<std::array<Prekey,PREKEY_AMOUNT>>(1));
		new (this->prekeys.get()) std::array<Prekey,PREKEY_AMOUNT>;
	}

	void PrekeyStore::generateKeys() {
		for (auto&& key : *this->prekeys) {
			key.generate();
		}
		this->updateExpirationDate();
	}

	PrekeyStore::PrekeyStore() {
		this->init();
		this->generateKeys();
	}

	PrekeyStore::PrekeyStore(
			ProtobufCPrekey ** const& keypairs,
			const size_t keypairs_length,
			ProtobufCPrekey ** const& deprecated_keypairs,
			const size_t deprecated_keypairs_length) {
		//check input
		if ((keypairs == nullptr)
				|| (keypairs_length != PREKEY_AMOUNT)
				|| ((deprecated_keypairs_length == 0) && (deprecated_keypairs != nullptr))
				|| ((deprecated_keypairs_length > 0) && (deprecated_keypairs == nullptr))) {
			throw Exception(INVALID_INPUT, "Invalid input to PrekeyStore_import");
		}

		this->init();

		for (size_t index = 0; index < keypairs_length; index++) {
			if (keypairs[index] == nullptr) {
				throw Exception(PROTOBUF_MISSING_ERROR, "Prekey missing.");
			}
			new (&(*this->prekeys)[index]) Prekey(*keypairs[index]);
		}

		for (size_t index = 0; index < deprecated_keypairs_length; index++) {
			if (deprecated_keypairs[index] == nullptr) {
				throw Exception(PROTOBUF_MISSING_ERROR, "Deprecated prekey missing.");
			}
			this->deprecated_prekeys.emplace_back(*deprecated_keypairs[index]);
		}

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();
	}

	static bool compare_expiration_dates(const Prekey& a, const Prekey& b) {
		if (a.expiration_date < b.expiration_date) {
			return true;
		}

		return false;
	}

	void PrekeyStore::updateExpirationDate() {
		const auto& oldest = std::min_element(std::cbegin(*this->prekeys), std::cend(*this->prekeys), compare_expiration_dates);
		this->oldest_expiration_date = oldest->expiration_date;
	}

	void PrekeyStore::updateDeprecatedExpirationDate() {
		if (this->deprecated_prekeys.empty()) {
			this->oldest_deprecated_expiration_date = 0;
			return;
		}

		const auto& oldest = std::min_element(std::cbegin(this->deprecated_prekeys), std::cend(this->deprecated_prekeys), compare_expiration_dates);
		this->oldest_deprecated_expiration_date = oldest->expiration_date;
	}

	void PrekeyStore::deprecate(const size_t index) {
		auto& at_index = (*this->prekeys)[index];
		at_index.expiration_date = time(nullptr) + DEPRECATED_PREKEY_EXPIRATION_TIME;
		this->deprecated_prekeys.push_back(at_index);

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();

		//generate new prekey
		at_index.generate();
	}

	void PrekeyStore::getPrekey(const PublicKey& public_key, PrivateKey& private_key) {
		//check buffers sizes
		if (public_key.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to PrekeyStore::getPrekey.");
		}

		//lambda for comparing PrekeyNodes to public_key
		auto key_comparer = [&public_key] (const Prekey& node) -> bool {
			return public_key == node.public_key;
		};

		auto found_prekey = std::find_if(std::cbegin(*this->prekeys), std::cend(*this->prekeys), key_comparer);
		if (found_prekey != this->prekeys->end()) {
			//copy the private key
			private_key = found_prekey->private_key;

			//and deprecate key
			size_t index = static_cast<size_t>(found_prekey - std::begin(*this->prekeys));
			this->deprecate(index);

			return;
		}

		auto found_deprecated_prekey = std::find_if(std::cbegin(this->deprecated_prekeys), std::cend(this->deprecated_prekeys), key_comparer);
		if (found_deprecated_prekey == this->deprecated_prekeys.end()) {
			private_key.empty = true;
			throw Exception(NOT_FOUND, "No matching prekey found.");
		}

		private_key = found_deprecated_prekey->private_key;
	}

	void PrekeyStore::list(Buffer& list) const { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		//check input
		if (!list.fits(PREKEY_AMOUNT * PUBLIC_KEY_SIZE)) {
			throw Exception(INVALID_INPUT, "Invalid input to PrekeyStore_list.");
		}

		size_t index = 0;
		for (const auto& key_bundle : *this->prekeys) {
			list.copyFromRaw(
					PUBLIC_KEY_SIZE * index,
					key_bundle.public_key.data(),
					0,
					PUBLIC_KEY_SIZE);
			index++;
		}
	}

	void PrekeyStore::rotate() {
		int64_t current_time = time(nullptr);

		//Is the expiration date too far into the future?
		if ((current_time + PREKEY_EXPIRATION_TIME) < this->oldest_expiration_date) {
			//TODO: Is this correct behavior?
			//Set the expiration date of everything to the current time + PREKEY_EXPIRATION_TIME
			for (auto&& prekey : *this->prekeys) {
				prekey.expiration_date = current_time + PREKEY_EXPIRATION_TIME;
			}
		}

		//Is the deprecated expiration date too far into the future?
		if ((current_time + DEPRECATED_PREKEY_EXPIRATION_TIME) < this->oldest_deprecated_expiration_date) {
			//Set the expiration date of everything to the current time + DEPRECATED_PREKEY_EXPIRATION_TIME
			for (auto&& prekey : this->deprecated_prekeys) {
				prekey.expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
			}
		}

		//At least one outdated prekey
		if (this->oldest_expiration_date < current_time) {
			for (auto&& prekey : *this->prekeys) {
				if (prekey.expiration_date < current_time) {
					size_t index = static_cast<size_t>(&prekey - &(*std::begin(*this->prekeys)));
					this->deprecate(index);
				}
			}
		}

		//At least one key to be removed
		if (this->oldest_deprecated_expiration_date < current_time) {
			for (size_t index = 0; index < this->deprecated_prekeys.size(); index++) {
				auto& prekey = this->deprecated_prekeys[index];
				if (prekey.expiration_date < current_time) {
					this->deprecated_prekeys.erase(std::cbegin(this->deprecated_prekeys) + static_cast<ptrdiff_t>(index));
					index--;
				}
			}
			this->updateDeprecatedExpirationDate();
		}
	}

	template <class Container>
	static void export_keypairs(Container& container, ProtobufCPrekey**& keypairs, size_t& keypairs_length) {
		if (container.size() == 0) {
			keypairs = nullptr;
			keypairs_length = 0;
			return;
		}

		auto prekeys = std::vector<std::unique_ptr<ProtobufCPrekey,PrekeyDeleter>>();
		prekeys.reserve(container.size());

		//export all buffers
		for (auto&& key : container) {
			prekeys.push_back(key.exportProtobuf());
		}

		//allocate output array
		keypairs = throwing_zeroed_malloc<ProtobufCPrekey*>(container.size());
		size_t index = 0;
		for (auto&& bundle : prekeys) {
			keypairs[index] = bundle.release();
			index++;
		}
		keypairs_length = container.size();
	}

	void PrekeyStore::exportProtobuf(
			ProtobufCPrekey**& keypairs,
			size_t& keypairs_length,
			ProtobufCPrekey**& deprecated_keypairs,
			size_t& deprecated_keypairs_length) const {
		//export prekeys
		export_keypairs(*this->prekeys, keypairs, keypairs_length);

		//export deprecated prekeys
		export_keypairs(this->deprecated_prekeys, deprecated_keypairs, deprecated_keypairs_length);
	}

	std::ostream& PrekeyStore::print(std::ostream& stream) const {

		stream << "Prekeys: [\n";
		for (const auto& prekey : *this->prekeys) {
			prekey.print(stream) <<  ",\n";
		}
		stream << "]\n";

		stream << "Deprecated Prekeys: [\n";
		for (const auto& prekey : this->deprecated_prekeys) {
			prekey.print(stream) << ",\n";
		}
		stream << "]\n";

		return stream;
	}
}
