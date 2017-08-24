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
#include <exception>
#include <memory>
#include <sstream>

#include "molch-exception.hpp"
#include "master-keys.hpp"
#include "spiced-random.hpp"
#include "sodium-wrappers.hpp"
#include "autozero.hpp"

namespace Molch {
	MasterKeys& MasterKeys::move(MasterKeys&& master_keys) {
		//move the private keys
		this->private_keys = std::move(master_keys.private_keys);
		this->private_identity_key = master_keys.private_identity_key;
		this->private_signing_key = master_keys.private_signing_key;

		this->public_identity_key = master_keys.public_identity_key;
		this->public_signing_key = master_keys.public_signing_key;

		return *this;
	}

	MasterKeys::MasterKeys(MasterKeys&& master_keys) {
		this->move(std::move(master_keys));
	}

	MasterKeys& MasterKeys::operator=(MasterKeys&& master_keys) {
		return this->move(std::move(master_keys));
	}

	MasterKeys::MasterKeys() {
		this->init();
		this->generate(nullptr);
	}

	MasterKeys::MasterKeys(const Buffer& low_entropy_seed) {
		this->init();
		this->generate(&low_entropy_seed);
	}

	MasterKeys::MasterKeys(
			const ProtobufCKey& public_signing_key,
			const ProtobufCKey& private_signing_key,
			const ProtobufCKey& public_identity_key,
			const ProtobufCKey& private_identity_key) {
		this->init();

		if ((this->private_signing_key == nullptr) || (this->private_identity_key == nullptr)) {
			throw Exception(INCORRECT_DATA, "One of the private key pointers is nullptr.");
		}

		ReadWriteUnlocker unlocker{*this};

		//copy the keys
		this->public_signing_key.set(public_signing_key.key.data, public_signing_key.key.len);
		this->public_identity_key.set(public_identity_key.key.data, public_identity_key.key.len);
		this->private_signing_key->set(private_signing_key.key.data, private_signing_key.key.len);
		this->private_identity_key->set(private_identity_key.key.data, private_identity_key.key.len);
	}


	void MasterKeys::init() {
		//allocate the private key storage
		this->private_keys = std::unique_ptr<PrivateMasterKeyStorage,SodiumDeleter<PrivateMasterKeyStorage>>(throwing_sodium_malloc<PrivateMasterKeyStorage>(1));

		//initialize the Buffers
		//private, initialize with pointers to private key storage
		this->private_identity_key = &this->private_keys->identity_key;
		this->private_signing_key = &this->private_keys->signing_key;

		//lock the private key storage
		this->lock();
	}

	void MasterKeys::generate(const Buffer* low_entropy_seed) {
		ReadWriteUnlocker unlocker{*this};

		if (low_entropy_seed != nullptr) {
			Buffer high_entropy_seed{
					crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
					crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
					&sodium_malloc,
					&sodium_free};
			spiced_random(high_entropy_seed, *low_entropy_seed, high_entropy_seed.capacity());

			//generate the signing keypair
			auto status{crypto_sign_seed_keypair(
					this->public_signing_key.data(),
					this->private_signing_key->data(),
					high_entropy_seed.content)};
			if (status != 0) {
				throw Exception(KEYGENERATION_FAILED, "Failed to generate signing keypair with seed.");
			}
			this->public_signing_key.empty = false;
			this->private_signing_key->empty = false;

			//generate the identity keypair
			status = crypto_box_seed_keypair(
					this->public_identity_key.data(),
					this->private_identity_key->data(),
					high_entropy_seed.content + crypto_sign_SEEDBYTES);
			if (status != 0) {
				throw Exception(KEYGENERATION_FAILED, "Failed to generate identity keypair with seed.");
			}
			this->public_identity_key.empty = false;
			this->private_identity_key->empty = false;
		} else { //don't use external seed
			//generate the signing keypair
			auto status{crypto_sign_keypair(
					this->public_signing_key.data(),
					this->private_signing_key->data())};
			if (status != 0) {
				throw Exception(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
			}
			this->public_signing_key.empty = false;
			this->private_signing_key->empty = false;

			//generate the identity keypair
			status = crypto_box_keypair(
					this->public_identity_key.data(),
					this->private_identity_key->data());
			if (status != 0) {
				throw Exception(KEYGENERATION_FAILED, "Failed to generate identity keypair.");
			}
			this->public_identity_key.empty = false;
			this->private_identity_key->empty = false;
		}
	}

	/*
	 * Get the public signing key.
	 */
	void MasterKeys::getSigningKey(PublicSigningKey& public_signing_key) const {
		public_signing_key = this->public_signing_key;
	}

	/*
	 * Get the public identity key.
	 */
	void MasterKeys::getIdentityKey(PublicKey& public_identity_key) const {
		public_identity_key = this->public_identity_key;
	}

	/*
	 * Sign a piece of data. Returns the data and signature in one output buffer.
	 */
	void MasterKeys::sign(
			const Buffer& data,
			Buffer& signed_data) const { //output, length of data + SIGNATURE_SIZE
		if (!signed_data.fits(data.size + SIGNATURE_SIZE)) {
			throw Exception(INVALID_INPUT, "MasterKeys::sign: Output buffer is too short.");
		}

		signed_data.size = 0;

		Unlocker unlocker{*this};
		unsigned long long signed_message_length;
		auto status{crypto_sign(
			signed_data.content,
			&signed_message_length,
			data.content,
			data.size,
			this->private_signing_key->data())};
		if (status != 0) {
			throw Exception(SIGN_ERROR, "Failed to sign message.");
		}

		signed_data.size = static_cast<size_t>(signed_message_length);
	}

	void MasterKeys::exportProtobuf(
			ProtobufPool& pool,
			ProtobufCKey*& public_signing_key,
			ProtobufCKey*& private_signing_key,
			ProtobufCKey*& public_identity_key,
			ProtobufCKey*& private_identity_key) const {
		//create and initialize the structs
		public_signing_key = pool.allocate<ProtobufCKey>(1);
		key__init(public_signing_key);
		private_signing_key = pool.allocate<ProtobufCKey>(1);
		key__init(private_signing_key);
		public_identity_key = pool.allocate<ProtobufCKey>(1);
		key__init(public_identity_key);
		private_identity_key = pool.allocate<ProtobufCKey>(1);
		key__init(private_identity_key);

		//allocate the key buffers
		public_signing_key->key.data = pool.allocate<uint8_t>(PUBLIC_MASTER_KEY_SIZE);
		public_signing_key->key.len = PUBLIC_MASTER_KEY_SIZE;
		private_signing_key->key.data = pool.allocate<uint8_t>(PRIVATE_MASTER_KEY_SIZE);
		private_signing_key->key.len = PRIVATE_MASTER_KEY_SIZE;
		public_identity_key->key.data = pool.allocate<uint8_t>(PUBLIC_KEY_SIZE);
		public_identity_key->key.len = PUBLIC_KEY_SIZE;
		private_identity_key->key.data = pool.allocate<uint8_t>(PRIVATE_KEY_SIZE);
		private_identity_key->key.len = PRIVATE_KEY_SIZE;

		//copy the keys
		this->public_signing_key.copyTo(public_signing_key->key.data, PUBLIC_MASTER_KEY_SIZE);
		this->public_identity_key.copyTo(public_identity_key->key.data, PUBLIC_KEY_SIZE);
		Unlocker unlocker{*this};
		this->private_signing_key->copyTo(private_signing_key->key.data, PRIVATE_MASTER_KEY_SIZE);
		this->private_identity_key->copyTo(private_identity_key->key.data, PRIVATE_KEY_SIZE);
	}

	void MasterKeys::lock() const {
		auto status{sodium_mprotect_noaccess(this->private_keys.get())};
		if (status != 0) {
			throw Exception(GENERIC_ERROR, "Failed to lock memory.");
		}
	}

	void MasterKeys::unlock() const {
		auto status{sodium_mprotect_readonly(this->private_keys.get())};
		if (status != 0) {
			throw Exception(GENERIC_ERROR, "Failed to make memory readonly.");
		}
	}

	void MasterKeys::unlock_readwrite() const {
		auto status{sodium_mprotect_readwrite(this->private_keys.get())};
		if (status != 0) {
			throw Exception(GENERIC_ERROR, "Failed to make memory readwrite.");
		}
	}

	std::ostream& MasterKeys::print(std::ostream& stream) const {
		Unlocker unlocker{*this};

		stream << "Public Signing Key:\n";
		this->public_signing_key.printHex(stream) << '\n';
		stream << "Private Signing Key:\n";
		this->private_signing_key->printHex(stream) << '\n';
		stream << "Public Identity Key:\n";
		this->public_identity_key.printHex(stream) << '\n';
		stream << "Private Identity Key:\n";
		this->private_identity_key->printHex(stream) << '\n';

		return stream;
	}

	MasterKeys::Unlocker::Unlocker(const MasterKeys& keys) : keys{keys} {
		this->keys.unlock();
	}

	MasterKeys::Unlocker::~Unlocker() {
		this->keys.lock();
	}

	MasterKeys::ReadWriteUnlocker::ReadWriteUnlocker(const MasterKeys& keys) : keys{keys} {
		this->keys.unlock_readwrite();
	}

	MasterKeys::ReadWriteUnlocker::~ReadWriteUnlocker() {
		this->keys.lock();
	}
}
