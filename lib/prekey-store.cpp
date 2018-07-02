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
#include "gsl.hpp"

namespace Molch {
	constexpr auto prekey_expiration_time{1_months};
	constexpr auto deprecated_prekey_expiration_time{1h};

	void Prekey::fill(const PublicKey& public_key, const PrivateKey& private_key, const seconds expiration_date) {
		this->expiration_date = expiration_date;
		this->public_key = public_key;
		this->private_key = private_key;
	}

	Prekey::Prekey(const PublicKey& public_key, const PrivateKey& private_key, const seconds expiration_date) {
		this->fill(public_key, private_key, expiration_date);
	}

	Prekey& Prekey::copy(const Prekey& node) noexcept {
		this->fill(node.public_key, node.private_key, node.expiration_date);

		return *this;
	}

	Prekey& Prekey::move(Prekey&& node) noexcept {
		return this->copy(node);
	}

	Prekey::Prekey(const Prekey& node) {
		this->copy(node);
	}

	Prekey::Prekey(Prekey&& node) noexcept {
		this->move(std::move(node));
	}

	Prekey& Prekey::operator=(const Prekey& node) noexcept {
		this->copy(node);
		return *this;
	}

	Prekey& Prekey::operator=(Prekey&& node) noexcept {
		this->move(std::move(node));
		return *this;
	}

	Prekey::Prekey(const ProtobufCPrekey& keypair) {
		//import private key
		if ((keypair.private_key == nullptr)
				|| (keypair.private_key->key.len != PRIVATE_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a private key."};
		}
		this->private_key = PrivateKey{*keypair.private_key};

		//import public key
		if (keypair.public_key == nullptr) {
			//public key is missing -> derive it from the private key
			TRY_VOID(crypto_scalarmult_base(this->public_key, this->private_key));
			this->public_key.empty = false;
		} else if (keypair.public_key->key.len != PUBLIC_KEY_SIZE) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a public key."};
		} else {
			this->public_key = PublicKey{*keypair.public_key};
		}

		//import expiration_date
		if (!keypair.has_expiration_time) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing an expiration time."};
		}
		this->expiration_date = seconds{keypair.expiration_time};
	}

	ProtobufCPrekey* Prekey::exportProtobuf(Arena& arena) const {
		protobuf_arena_create(arena, ProtobufCPrekey, prekey);

		prekey->private_key = this->private_key.exportProtobuf(arena);

		//export the public key
		prekey->public_key = this->public_key.exportProtobuf(arena);
		//export the expiration date
		protobuf_optional_export(prekey, expiration_time, gsl::narrow<uint64_t>(this->expiration_date.count()));

		return prekey;
	}

	seconds Prekey::expirationDate() const {
		return this->expiration_date;
	}
	const PublicKey& Prekey::publicKey() const {
		return this->public_key;
	}
	const PrivateKey& Prekey::privateKey() const {
		return this->private_key;
	}

	void Prekey::generate() {
		TRY_VOID(crypto_box_keypair(
				this->public_key,
				this->private_key));
		this->public_key.empty = false;
		this->private_key.empty = false;
		this->expiration_date = now() + prekey_expiration_time;
	}

	std::ostream& Prekey::print(std::ostream& stream) const {
		stream << "Expiration Date = " << this->expiration_date.count() << "s" << '\n';
		stream << "Public Prekey:\n";
		this->public_key.printHex(stream) << '\n';
		stream << "Private Prekey:\n";
		this->private_key.printHex(stream) << '\n';

		return stream;
	}

	void PrekeyStore::init() {
		this->prekeys_storage = std::unique_ptr<std::array<Prekey,PREKEY_AMOUNT>,SodiumDeleter<std::array<Prekey,PREKEY_AMOUNT>>>(sodium_malloc<std::array<Prekey,PREKEY_AMOUNT>>(1));
		new (this->prekeys_storage.get()) std::array<Prekey,PREKEY_AMOUNT>;
	}

	void PrekeyStore::generateKeys() {
		for (auto& key : *this->prekeys_storage) {
			key.generate();
		}
		this->updateExpirationDate();
	}

	PrekeyStore::PrekeyStore() {
		this->init();
		this->generateKeys();
	}

	PrekeyStore::PrekeyStore(
			const span<ProtobufCPrekey*> keypairs,
			const span<ProtobufCPrekey*> deprecated_keypairs) {
		Expects(keypairs.size() == PREKEY_AMOUNT);

		this->init();

		size_t index{0};
		for (auto const& keypair : keypairs) {
			if (keypair == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Prekey missing."};
			}
			new (&(*this->prekeys_storage)[index]) Prekey(*keypair);
			++index;
		}

		for (auto const& keypair : deprecated_keypairs) {
			if (keypair == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Deprecated prekey missing."};
			}
			this->deprecated_prekeys_storage.emplace_back(*keypair);
		}

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();
	}

	static bool compare_expiration_dates(const Prekey& a, const Prekey& b) {
		return a.expirationDate() < b.expirationDate();
	}

	void PrekeyStore::updateExpirationDate() {
		const auto& oldest{std::min_element(std::cbegin(*this->prekeys_storage), std::cend(*this->prekeys_storage), compare_expiration_dates)};
		this->oldest_expiration_date = oldest->expiration_date;
	}

	void PrekeyStore::updateDeprecatedExpirationDate() {
		if (this->deprecated_prekeys_storage.empty()) {
			this->oldest_deprecated_expiration_date = 0s;
			return;
		}

		const auto& oldest = std::min_element(std::cbegin(this->deprecated_prekeys_storage), std::cend(this->deprecated_prekeys_storage), compare_expiration_dates);
		this->oldest_deprecated_expiration_date = oldest->expiration_date;
	}

	void PrekeyStore::deprecate(const size_t index) {
		auto& at_index{(*this->prekeys_storage)[index]};
		at_index.expiration_date = now() + deprecated_prekey_expiration_time;
		this->deprecated_prekeys_storage.push_back(at_index);

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();

		//generate new prekey
		at_index.generate();
	}

	void PrekeyStore::getPrekey(const PublicKey& public_key, PrivateKey& private_key) {
		Expects(!public_key.empty);

		//lambda for comparing PrekeyNodes to public_key
		auto key_comparer{[&public_key] (const Prekey& node) -> bool {
			return public_key == node.public_key;
		}};

		auto found_prekey{std::find_if(std::cbegin(*this->prekeys_storage), std::cend(*this->prekeys_storage), key_comparer)};
		if (found_prekey != this->prekeys_storage->end()) {
			//copy the private key
			private_key = found_prekey->private_key;

			//and deprecate key
			auto index{gsl::narrow_cast<size_t>(found_prekey - std::begin(*this->prekeys_storage))};
			this->deprecate(index);

			return;
		}

		auto found_deprecated_prekey{std::find_if(std::cbegin(this->deprecated_prekeys_storage), std::cend(this->deprecated_prekeys_storage), key_comparer)};
		if (found_deprecated_prekey == this->deprecated_prekeys_storage.end()) {
			private_key.empty = true;
			throw Exception{status_type::NOT_FOUND, "No matching prekey found."};
		}

		private_key = found_deprecated_prekey->private_key;
	}

	void PrekeyStore::list(span<std::byte> list) const { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		Expects(list.size() == PREKEY_AMOUNT * PUBLIC_KEY_SIZE);

		size_t index{0};
		for (const auto& key_bundle : *this->prekeys_storage) {
			auto key_span{key_bundle.public_key};
			std::copy(std::cbegin(key_span), std::cend(key_span), std::begin(list) + gsl::narrow_cast<ptrdiff_t>(PUBLIC_KEY_SIZE * index));
			index++;
		}
	}

	void PrekeyStore::rotate() {
		seconds current_time{now()};

		//Is the expiration date too far into the future?
		if ((current_time + prekey_expiration_time) < this->oldest_expiration_date) {
			//TODO: Is this correct behavior?
			//Set the expiration date of everything to the current time + PREKEY_EXPIRATION_TIME
			for (auto& prekey : *this->prekeys_storage) {
				prekey.expiration_date = current_time + prekey_expiration_time;
			}
		}

		//Is the deprecated expiration date too far into the future?
		if ((current_time + deprecated_prekey_expiration_time) < this->oldest_deprecated_expiration_date) {
			//Set the expiration date of everything to the current time + DEPRECATED_PREKEY_EXPIRATION_TIME
			for (auto& prekey : this->deprecated_prekeys_storage) {
				prekey.expiration_date = current_time + deprecated_prekey_expiration_time;
			}
		}

		//At least one outdated prekey
		if (this->oldest_expiration_date < current_time) {
			size_t index{0};
			for (size_t index{0}; index < this->prekeys_storage->size(); ++index) {
			}
			for (const auto& prekey : *this->prekeys_storage) {
				if (prekey.expiration_date < current_time) {
					this->deprecate(index);
				}
				index++;
			}
		}

		//At least one key to be removed
		if (this->oldest_deprecated_expiration_date < current_time) {
			for (size_t index{0}; index < this->deprecated_prekeys_storage.size(); index++) {
				auto& prekey = this->deprecated_prekeys_storage[index];
				if (prekey.expiration_date < current_time) {
					this->deprecated_prekeys_storage.erase(std::cbegin(this->deprecated_prekeys_storage) + gsl::narrow_cast<ptrdiff_t>(index));
					index--;
				}
			}
			this->updateDeprecatedExpirationDate();
		}
	}

	template <class Container>
	static void export_keypairs(Arena& arena, Container& container, span<ProtobufCPrekey*>& keypairs) {
		if (container.empty()) {
			keypairs = {nullptr, static_cast<size_t>(0)};
			return;
		}

		//export all buffers
		auto keypairs_array{arena.allocate<ProtobufCPrekey*>(container.size())};
		size_t index{0};
		for (const auto& key : container) {
			keypairs_array[index] = key.exportProtobuf(arena);
			index++;
		}
		keypairs = {keypairs_array, container.size()};
	}

	void PrekeyStore::exportProtobuf(
			Arena& arena,
			span<ProtobufCPrekey*>& keypairs,
			span<ProtobufCPrekey*>& deprecated_keypairs) const {
		//export prekeys
		export_keypairs(arena, *this->prekeys_storage, keypairs);

		//export deprecated prekeys
		export_keypairs(arena, this->deprecated_prekeys_storage, deprecated_keypairs);
	}

	std::ostream& PrekeyStore::print(std::ostream& stream) const {

		stream << "Prekeys: [\n";
		for (const auto& prekey : *this->prekeys_storage) {
			prekey.print(stream) <<  ",\n";
		}
		stream << "]\n";

		stream << "Deprecated Prekeys: [\n";
		for (const auto& prekey : this->deprecated_prekeys_storage) {
			prekey.print(stream) << ",\n";
		}
		stream << "]\n";

		return stream;
	}

	const std::array<Prekey,PREKEY_AMOUNT>& PrekeyStore::prekeys() const {
		return *this->prekeys_storage;
	}
	const std::vector<Prekey,SodiumAllocator<Prekey>>& PrekeyStore::deprecatedPrekeys() const {
		return this->deprecated_prekeys_storage;
	}
	const seconds& PrekeyStore::oldestExpirationDate() const {
		return this->oldest_expiration_date;
	}
	const seconds& PrekeyStore::oldestDeprecatedExpirationDate() const {
		return this->oldest_deprecated_expiration_date;
	}

	void PrekeyStore::timeshiftForTestingOnly(size_t index, seconds timeshift) {
		if (!this->prekeys_storage) {
			throw Exception{status_type::INCORRECT_DATA, "The prekey storage is null."};
		}
		(*this->prekeys_storage)[index].expiration_date += timeshift;
		this->updateExpirationDate();
	}

	void PrekeyStore::timeshiftDeprecatedForTestingOnly(size_t index, seconds timeshift) {
		this->deprecated_prekeys_storage[index].expiration_date += timeshift;
		this->updateDeprecatedExpirationDate();
	}
}
