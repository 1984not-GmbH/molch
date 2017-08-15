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

constexpr int64_t PREKEY_EXPIRATION_TIME = 3600 * 24 * 31; //one month
constexpr int64_t DEPRECATED_PREKEY_EXPIRATION_TIME = 3600; //one hour

void PrekeyStoreNode::fill(const Buffer& public_key, const Buffer& private_key, const int64_t expiration_date) {
	this->expiration_date = expiration_date;
	if (this->public_key.cloneFrom(&public_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public key.");
	}
	if (this->private_key.cloneFrom(&private_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy private key.");
	}
}

PrekeyStoreNode::PrekeyStoreNode(const Buffer& public_key, const Buffer& private_key, int64_t expiration_date) {
	this->fill(public_key, private_key, expiration_date);
}

PrekeyStoreNode& PrekeyStoreNode::copy(const PrekeyStoreNode& node) {
	this->fill(node.public_key, node.private_key, node.expiration_date);

	return *this;
}

PrekeyStoreNode& PrekeyStoreNode::move(PrekeyStoreNode&& node) {
	return this->copy(node);
}

PrekeyStoreNode::PrekeyStoreNode(const PrekeyStoreNode& node) {
	this->copy(node);
}

PrekeyStoreNode::PrekeyStoreNode(PrekeyStoreNode&& node) {
	this->move(std::move(node));
}

PrekeyStoreNode& PrekeyStoreNode::operator=(const PrekeyStoreNode& node) {
	return this->copy(node);
}

PrekeyStoreNode& PrekeyStoreNode::operator=(PrekeyStoreNode&& node) {
	return this->move(std::move(node));
}

PrekeyStoreNode::PrekeyStoreNode(const Prekey& keypair) {
	//import private key
	if ((keypair.private_key == nullptr)
			|| (keypair.private_key->key.len != PRIVATE_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a private key.");
	}
	if (this->private_key.cloneFromRaw(keypair.private_key->key.data, keypair.private_key->key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy private key from protobuf.");
	}

	//import public key
	if (keypair.public_key == nullptr) {
		//public key is missing -> derive it from the private key
		if (crypto_scalarmult_base(this->public_key.content, this->private_key.content) != 0) {
			throw MolchException(KEYDERIVATION_FAILED, "Failed to derive public prekey from private one.");
		}
		this->public_key.content_length = PUBLIC_KEY_SIZE;
	} else if (keypair.public_key->key.len != PUBLIC_KEY_SIZE) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing a public key.");
	} else {
		if (this->public_key.cloneFromRaw(keypair.public_key->key.data, keypair.public_key->key.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy public key from protobuf.");
		}
	}

	//import expiration_date
	if (!keypair.has_expiration_time) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "Prekey protobuf is missing an expiration time.");
	}
	this->expiration_date = static_cast<int64_t>(keypair.expiration_time);
}

std::unique_ptr<Prekey,PrekeyDeleter> PrekeyStoreNode::exportProtobuf() const {
	auto prekey = std::unique_ptr<Prekey,PrekeyDeleter>(throwing_zeroed_malloc<Prekey>(sizeof(Prekey)));
	prekey__init(prekey.get());

	//export the private key
	prekey->private_key = throwing_zeroed_malloc<Key>(sizeof(Key));
	key__init(prekey->private_key);
	prekey->private_key->key.data = throwing_zeroed_malloc<uint8_t>(PRIVATE_KEY_SIZE);
	prekey->private_key->key.len = PRIVATE_KEY_SIZE;
	if (this->private_key.cloneToRaw(prekey->private_key->key.data, prekey->private_key->key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy private key to protobuf.");
	}

	//export the public key
	prekey->public_key = throwing_zeroed_malloc<Key>(sizeof(Key));
	key__init(prekey->public_key);
	prekey->public_key->key.data = throwing_zeroed_malloc<uint8_t>(PUBLIC_KEY_SIZE);
	prekey->public_key->key.len = PUBLIC_KEY_SIZE;
	if (this->public_key.cloneToRaw(prekey->public_key->key.data, prekey->public_key->key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public key to protobuf.");
	}

	//export the expiration date
	prekey->expiration_time = static_cast<uint64_t>(this->expiration_date);
	prekey->has_expiration_time = true;

	return prekey;
}

void PrekeyStoreNode::generate() {
	if (this->public_key.content == nullptr) {
		throw MolchException(INVALID_INPUT, "public key is nullptr");
	}
	if (this->public_key.content == nullptr) {
		throw MolchException(INVALID_INPUT, "private key is nullptr");
	}
	int status = crypto_box_keypair(
		this->public_key.content,
		this->private_key.content);
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate prekey pair.");
	}
	this->public_key.content_length = PUBLIC_KEY_SIZE;
	this->private_key.content_length = PRIVATE_KEY_SIZE;
	this->expiration_date = time(nullptr) + PREKEY_EXPIRATION_TIME;
}

std::ostream& PrekeyStoreNode::print(std::ostream& stream) const {
	stream << "Expiration Date = " << std::to_string(this->expiration_date) << '\n';
	stream << "Public Prekey:\n";
	stream << this->public_key.toHex() << '\n';
	stream << "Private Prekey:\n";
	stream << this->private_key.toHex() << '\n';

	return stream;
}

void PrekeyStore::init() {
	this->prekeys = std::unique_ptr<std::array<PrekeyStoreNode,PREKEY_AMOUNT>,SodiumDeleter<std::array<PrekeyStoreNode,PREKEY_AMOUNT>>>(throwing_sodium_malloc<std::array<PrekeyStoreNode,PREKEY_AMOUNT>>(sizeof(std::array<PrekeyStoreNode,PREKEY_AMOUNT>)));
	new (this->prekeys.get()) std::array<PrekeyStoreNode,PREKEY_AMOUNT>{};
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
		Prekey ** const& keypairs,
		const size_t keypairs_length,
		Prekey ** const& deprecated_keypairs,
		const size_t deprecated_keypairs_length) {
	//check input
	if ((keypairs == nullptr)
			|| (keypairs_length != PREKEY_AMOUNT)
			|| ((deprecated_keypairs_length == 0) && (deprecated_keypairs != nullptr))
			|| ((deprecated_keypairs_length > 0) && (deprecated_keypairs == nullptr))) {
		throw MolchException(INVALID_INPUT, "Invalid input to PrekeyStore_import");
	}

	this->init();

	for (size_t index = 0; index < keypairs_length; index++) {
		if (keypairs[index] == nullptr) {
			throw MolchException(PROTOBUF_MISSING_ERROR, "Prekey missing.");
		}
		(*this->prekeys)[index] = PrekeyStoreNode(*keypairs[index]);
	}

	for (size_t index = 0; index < deprecated_keypairs_length; index++) {
		if (deprecated_keypairs[index] == nullptr) {
			throw MolchException(PROTOBUF_MISSING_ERROR, "Deprecated prekey missing.");
		}
		this->deprecated_prekeys.emplace_back(*deprecated_keypairs[index]);
	}

	this->updateExpirationDate();
	this->updateDeprecatedExpirationDate();
}

static bool compare_expiration_dates(const PrekeyStoreNode& a, const PrekeyStoreNode& b) {
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

void PrekeyStore::getPrekey(const Buffer& public_key, Buffer& private_key) {
	//check buffers sizes
	if (!public_key.contains(PUBLIC_KEY_SIZE) || !private_key.fits(PRIVATE_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to PrekeyStore::getPrekey.");
	}

	//lambda for comparing PrekeyNodes to public_key
	auto key_comparer = [&public_key] (const PrekeyStoreNode& node) -> bool {
		return public_key == node.public_key;
	};

	auto found_prekey = std::find_if(std::cbegin(*this->prekeys), std::cend(*this->prekeys), key_comparer);
	if (found_prekey != this->prekeys->end()) {
		//copy the private key
		if (private_key.cloneFrom(&found_prekey->private_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to clone private key from prekey.");
		}

		//and deprecate key
		size_t index = static_cast<size_t>(found_prekey - std::begin(*this->prekeys));
		this->deprecate(index);

		return;
	}

	auto found_deprecated_prekey = std::find_if(std::cbegin(this->deprecated_prekeys), std::cend(this->deprecated_prekeys), key_comparer);
	if (found_deprecated_prekey == this->deprecated_prekeys.end()) {
		private_key.content_length = 0;
		throw MolchException(NOT_FOUND, "No matching prekey found.");
	}

	if (private_key.cloneFrom(&found_deprecated_prekey->private_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to clone private key from deprecated prekey.");
	}
}

void PrekeyStore::list(Buffer& list) const { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
	//check input
	if (!list.fits(PREKEY_AMOUNT * PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to PrekeyStore_list.");
	}

	size_t index = 0;
	for (const auto& key_bundle : *this->prekeys) {
		int status = list.copyFrom(
				PUBLIC_KEY_SIZE * index,
				&key_bundle.public_key,
				0,
				PUBLIC_KEY_SIZE);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy public prekey.");
		}
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
static void export_keypairs(Container& container, Prekey**& keypairs, size_t& keypairs_length) {
	if (container.size() == 0) {
		keypairs = nullptr;
		keypairs_length = 0;
		return;
	}

	auto prekeys = std::vector<std::unique_ptr<Prekey,PrekeyDeleter>>();
	prekeys.reserve(container.size());

	//export all buffers
	for (auto&& key : container) {
		prekeys.push_back(key.exportProtobuf());
	}

	//allocate output array
	keypairs = throwing_zeroed_malloc<Prekey*>(container.size() * sizeof(Prekey*));
	size_t index = 0;
	for (auto&& bundle : prekeys) {
		keypairs[index] = bundle.release();
		index++;
	}
	keypairs_length = container.size();
}

void PrekeyStore::exportProtobuf(
		Prekey**& keypairs,
		size_t& keypairs_length,
		Prekey**& deprecated_keypairs,
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

