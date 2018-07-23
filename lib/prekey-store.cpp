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

	void Prekey::fill(const PublicKey& public_key, const PrivateKey& private_key, const seconds expiration_date) noexcept {
		this->expiration_date = expiration_date;
		this->public_key = public_key;
		this->private_key = private_key;
	}

	Prekey::Prekey(const PublicKey& public_key, const PrivateKey& private_key, const seconds expiration_date) noexcept {
		this->fill(public_key, private_key, expiration_date);
	}

	Prekey& Prekey::copy(const Prekey& node) noexcept {
		this->fill(node.public_key, node.private_key, node.expiration_date);

		return *this;
	}

	Prekey& Prekey::move(Prekey&& node) noexcept {
		return this->copy(node);
	}

	Prekey::Prekey(const Prekey& node) noexcept {
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

	result<Prekey> Prekey::import(const ProtobufCPrekey& keypair) {
		//import private key
		if ((keypair.private_key == nullptr)
				|| (keypair.private_key->key.len != PRIVATE_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a private key.");
		}
		Prekey prekey;
		prekey.private_key = PrivateKey{*keypair.private_key};

		//import public key
		if (keypair.public_key == nullptr) {
			//public key is missing -> derive it from the private key
			OUTCOME_TRY(crypto_scalarmult_base(prekey.public_key, prekey.private_key));
			prekey.public_key.empty = false;
		} else if (keypair.public_key->key.len != PUBLIC_KEY_SIZE) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a public key.");
		} else {
			prekey.public_key = PublicKey{*keypair.public_key};
		}

		//import expiration_date
		if (!keypair.has_expiration_time) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing an expiration time.");
		}
		prekey.expiration_date = seconds{keypair.expiration_time};

		return prekey;
	}

	result<ProtobufCPrekey*> Prekey::exportProtobuf(Arena& arena) const {
		protobuf_arena_create(arena, ProtobufCPrekey, prekey);

		OUTCOME_TRY(private_key, this->private_key.exportProtobuf(arena));
		prekey->private_key = private_key;

		//export the public key
		OUTCOME_TRY(public_key, this->public_key.exportProtobuf(arena));
		prekey->public_key = public_key;
		//export the expiration date
		protobuf_optional_export(prekey, expiration_time, gsl::narrow<uint64_t>(this->expiration_date.count()));

		return prekey;
	}

	seconds Prekey::expirationDate() const noexcept {
		return this->expiration_date;
	}
	const PublicKey& Prekey::publicKey() const noexcept {
		return this->public_key;
	}
	const PrivateKey& Prekey::privateKey() const noexcept {
		return this->private_key;
	}

	result<void> Prekey::generate() noexcept {
		OUTCOME_TRY(crypto_box_keypair(
				this->public_key,
				this->private_key));
		this->public_key.empty = false;
		this->private_key.empty = false;
		this->expiration_date = now() + prekey_expiration_time;

		return outcome::success();
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

	result<void> PrekeyStore::generateKeys() {
		for (auto& key : *this->prekeys_storage) {
			OUTCOME_TRY(key.generate());
		}
		this->updateExpirationDate();

		return outcome::success();
	}

	PrekeyStore::PrekeyStore() {
		this->init();
		TRY_VOID(this->generateKeys());
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
			TRY_WITH_RESULT(imported_prekey, Prekey::import(*keypair));
			new (&(*this->prekeys_storage)[index]) Prekey(std::move(imported_prekey.value()));
			++index;
		}

		for (auto const& keypair : deprecated_keypairs) {
			if (keypair == nullptr) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Deprecated prekey missing."};
			}
			TRY_WITH_RESULT(imported_prekey, Prekey::import(*keypair));
			this->deprecated_prekeys_storage.emplace_back(std::move(imported_prekey.value()));
		}

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();
	}

	static bool compare_expiration_dates(const Prekey& a, const Prekey& b) noexcept {
		return a.expirationDate() < b.expirationDate();
	}

	void PrekeyStore::updateExpirationDate() noexcept {
		const auto& oldest{std::min_element(std::cbegin(*this->prekeys_storage), std::cend(*this->prekeys_storage), compare_expiration_dates)};
		this->oldest_expiration_date = oldest->expiration_date;
	}

	void PrekeyStore::updateDeprecatedExpirationDate() noexcept {
		if (this->deprecated_prekeys_storage.empty()) {
			this->oldest_deprecated_expiration_date = 0s;
			return;
		}

		const auto& oldest = std::min_element(std::cbegin(this->deprecated_prekeys_storage), std::cend(this->deprecated_prekeys_storage), compare_expiration_dates);
		this->oldest_deprecated_expiration_date = oldest->expiration_date;
	}

	result<void> PrekeyStore::deprecate(const size_t index) {
		auto& at_index{(*this->prekeys_storage)[index]};
		at_index.expiration_date = now() + deprecated_prekey_expiration_time;
		this->deprecated_prekeys_storage.push_back(at_index);

		this->updateExpirationDate();
		this->updateDeprecatedExpirationDate();

		//generate new prekey
		OUTCOME_TRY(at_index.generate());

		return outcome::success();
	}

	result<PrivateKey> PrekeyStore::getPrekey(const PublicKey& public_key) {
		FulfillOrFail(!public_key.empty);

		//lambda for comparing PrekeyNodes to public_key
		auto key_comparer{[&public_key] (const Prekey& node) -> bool {
			return public_key == node.public_key;
		}};

		auto found_prekey{std::find_if(std::cbegin(*this->prekeys_storage), std::cend(*this->prekeys_storage), key_comparer)};
		if (found_prekey != this->prekeys_storage->end()) {
			//copy the private key
			auto private_key{found_prekey->private_key};

			//and deprecate key
			auto index{gsl::narrow_cast<size_t>(found_prekey - std::begin(*this->prekeys_storage))};
			OUTCOME_TRY(this->deprecate(index));

			return private_key;
		}

		auto found_deprecated_prekey{std::find_if(std::cbegin(this->deprecated_prekeys_storage), std::cend(this->deprecated_prekeys_storage), key_comparer)};
		if (found_deprecated_prekey == this->deprecated_prekeys_storage.end()) {
			return Error(status_type::NOT_FOUND, "No matching prekey found.");
		}

		return found_deprecated_prekey->private_key;
	}

	result<Buffer> PrekeyStore::list() const { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		const auto buffer_length{PREKEY_AMOUNT * PUBLIC_KEY_SIZE};
		Buffer list(buffer_length, buffer_length);

		size_t index{0};
		for (const auto& key_bundle : *this->prekeys_storage) {
			auto key_span{key_bundle.public_key};
			std::copy(std::cbegin(key_span), std::cend(key_span), std::begin(list) + gsl::narrow_cast<ptrdiff_t>(PUBLIC_KEY_SIZE * index));
			index++;
		}

		return std::move(list);
	}

	result<void> PrekeyStore::rotate() {
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
					OUTCOME_TRY(this->deprecate(index));
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

		return outcome::success();
	}

	template <class Container>
	static result<span<ProtobufCPrekey*>> export_keypairs(Arena& arena, const Container& container) {
		if (container.empty()) {
			return {nullptr, static_cast<size_t>(0)};
		}

		//export all buffers
		auto keypairs_array{arena.allocate<ProtobufCPrekey*>(container.size())};
		size_t index{0};
		for (const auto& key : container) {
			TRY_WITH_RESULT(exported_prekey, key.exportProtobuf(arena));
			keypairs_array[index] = exported_prekey.value();
			index++;
		}
		return {keypairs_array, container.size()};
	}

	result<PrekeyStore::ExportedPrekeyStore> PrekeyStore::exportProtobuf(Arena& arena) const {
		ExportedPrekeyStore prekey_store;
		OUTCOME_TRY(keypairs, export_keypairs(arena, *this->prekeys_storage));
		prekey_store.keypairs = keypairs;
		OUTCOME_TRY(deprecated_keypairs, export_keypairs(arena, this->deprecated_prekeys_storage));
		prekey_store.deprecated_keypairs = deprecated_keypairs;

		return prekey_store;
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

	const std::array<Prekey,PREKEY_AMOUNT>& PrekeyStore::prekeys() const noexcept {
		return *this->prekeys_storage;
	}
	const std::vector<Prekey,SodiumAllocator<Prekey>>& PrekeyStore::deprecatedPrekeys() const noexcept {
		return this->deprecated_prekeys_storage;
	}
	const seconds& PrekeyStore::oldestExpirationDate() const noexcept {
		return this->oldest_expiration_date;
	}
	const seconds& PrekeyStore::oldestDeprecatedExpirationDate() const noexcept {
		return this->oldest_deprecated_expiration_date;
	}

	result<void> PrekeyStore::timeshiftForTestingOnly(size_t index, seconds timeshift) {
		if (!this->prekeys_storage) {
			return Error(status_type::INCORRECT_DATA, "The prekey storage is null.");
		}
		(*this->prekeys_storage)[index].expiration_date += timeshift;
		this->updateExpirationDate();

		return outcome::success();
	}

	void PrekeyStore::timeshiftDeprecatedForTestingOnly(size_t index, seconds timeshift) noexcept {
		this->deprecated_prekeys_storage[index].expiration_date += timeshift;
		this->updateDeprecatedExpirationDate();
	}
}
