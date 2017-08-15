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

MasterKeys& MasterKeys::move(MasterKeys&& master_keys) {
	//move the private keys
	this->private_keys = std::move(master_keys.private_keys);
	this->private_identity_key = Buffer{this->private_keys->identity_key, master_keys.private_identity_key.content_length, sizeof(this->private_keys->identity_key)};
	this->private_signing_key = Buffer{this->private_keys->signing_key, master_keys.private_signing_key.content_length, sizeof(this->private_keys->signing_key)};

	if (this->public_identity_key.cloneFrom(&master_keys.public_identity_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public identity key.");
	}
	if (this->public_signing_key.cloneFrom(&master_keys.public_signing_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public signing key.");
	}

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
		const Key& public_signing_key,
		const Key& private_signing_key,
		const Key& public_identity_key,
		const Key& private_identity_key) {
	this->init();

	ReadWriteUnlocker unlocker(*this);

	//copy the keys
	if (this->public_signing_key.cloneFromRaw(public_signing_key.key.data, public_signing_key.key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public signing key.");
	}
	if (this->public_identity_key.cloneFromRaw(public_identity_key.key.data, public_identity_key.key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public identity key.");
	}
	if (this->private_signing_key.cloneFromRaw(private_signing_key.key.data, private_signing_key.key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy private signing key.");
	}
	if (this->private_identity_key.cloneFromRaw(private_identity_key.key.data, private_identity_key.key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy private identity key.");
	}
}


void MasterKeys::init() {
	//allocate the private key storage
	this->private_keys = std::unique_ptr<PrivateMasterKeyStorage,SodiumDeleter<PrivateMasterKeyStorage>>(throwing_sodium_malloc<PrivateMasterKeyStorage>(sizeof(PrivateMasterKeyStorage)));

	//initialize the Buffers
	//private, initialize with pointers to private key storage
	new (&this->private_identity_key) Buffer{this->private_keys->identity_key, sizeof(this->private_keys->identity_key), 0};
	new (&this->private_signing_key) Buffer{this->private_keys->signing_key, sizeof(this->private_keys->signing_key), 0};

	//lock the private key storage
	this->lock();
}

void MasterKeys::generate(const Buffer* low_entropy_seed) {
	ReadWriteUnlocker unlocker(*this);

	if (low_entropy_seed != nullptr) {
		Buffer high_entropy_seed(
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				&sodium_malloc,
				&sodium_free);
		exception_on_invalid_buffer(high_entropy_seed);

		spiced_random(high_entropy_seed, *low_entropy_seed, high_entropy_seed.getBufferLength());

		//generate the signing keypair
		int status = crypto_sign_seed_keypair(
				this->public_signing_key.content,
				this->private_signing_key.content,
				high_entropy_seed.content);
		if (status != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate signing keypair with seed.");
		}
		this->public_signing_key.content_length = PUBLIC_MASTER_KEY_SIZE;
		this->private_signing_key.content_length = PRIVATE_MASTER_KEY_SIZE;

		//generate the identity keypair
		status = crypto_box_seed_keypair(
				this->public_identity_key.content,
				this->private_identity_key.content,
				high_entropy_seed.content + crypto_sign_SEEDBYTES);
		if (status != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate identity keypair with seed.");
		}
		this->public_identity_key.content_length = PUBLIC_KEY_SIZE;
		this->private_identity_key.content_length = PRIVATE_KEY_SIZE;
	} else { //don't use external seed
		//generate the signing keypair
		int status = crypto_sign_keypair(
				this->public_signing_key.content,
				this->private_signing_key.content);
		if (status != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
		}
		this->public_signing_key.content_length = PUBLIC_MASTER_KEY_SIZE;
		this->private_signing_key.content_length = PRIVATE_MASTER_KEY_SIZE;

		//generate the identity keypair
		status = crypto_box_keypair(
				this->public_identity_key.content,
				this->private_identity_key.content);
		if (status != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate identity keypair.");
		}
		this->public_identity_key.content_length = PUBLIC_KEY_SIZE;
		this->private_identity_key.content_length = PRIVATE_KEY_SIZE;
	}
}

/*
 * Get the public signing key.
 */
void MasterKeys::getSigningKey(Buffer& public_signing_key) const {
	//check input
	if (!public_signing_key.fits(PUBLIC_MASTER_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "MasterKeys::getSigningKey: Output buffer is too short.");
	}

	if (public_signing_key.cloneFrom(&this->public_signing_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public signing key.");
	}
}

/*
 * Get the public identity key.
 */
void MasterKeys::getIdentityKey(Buffer& public_identity_key) const {
	//check input
	if (!public_identity_key.fits(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "MasterKeys::getIdentityKey: Output buffer is too short.");
	}

	if (public_identity_key.cloneFrom(&this->public_identity_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public identity key.");
	}
}

/*
 * Sign a piece of data. Returns the data and signature in one output buffer.
 */
void MasterKeys::sign(
		const Buffer& data,
		Buffer& signed_data) const { //output, length of data + SIGNATURE_SIZE
	if (!signed_data.fits(data.content_length + SIGNATURE_SIZE)) {
		throw MolchException(INVALID_INPUT, "MasterKeys::sign: Output buffer is too short.");
	}

	signed_data.content_length = 0;

	Unlocker unlocker(*this);
	unsigned long long signed_message_length;
	int status_int = crypto_sign(
		signed_data.content,
		&signed_message_length,
		data.content,
		data.content_length,
		this->private_signing_key.content);
	if (status_int != 0) {
		throw MolchException(SIGN_ERROR, "Failed to sign message.");
	}

	signed_data.content_length = static_cast<size_t>(signed_message_length);
}

void MasterKeys::exportProtobuf(
		std::unique_ptr<Key,KeyDeleter>& public_signing_key,
		std::unique_ptr<Key,KeyDeleter>& private_signing_key,
		std::unique_ptr<Key,KeyDeleter>& public_identity_key,
		std::unique_ptr<Key,KeyDeleter>& private_identity_key) const {
	//create and initialize the structs
	public_signing_key = std::unique_ptr<Key,KeyDeleter>(throwing_zeroed_malloc<Key>(sizeof(Key)));
	key__init(public_signing_key.get());
	private_signing_key = std::unique_ptr<Key,KeyDeleter>(throwing_zeroed_malloc<Key>(sizeof(Key)));
	key__init(private_signing_key.get());
	public_identity_key = std::unique_ptr<Key,KeyDeleter>(throwing_zeroed_malloc<Key>(sizeof(Key)));
	key__init(public_identity_key.get());
	private_identity_key = std::unique_ptr<Key,KeyDeleter>(throwing_zeroed_malloc<Key>(sizeof(Key)));
	key__init(private_identity_key.get());

	//allocate the key buffers
	public_signing_key->key.data = throwing_zeroed_malloc<uint8_t>(PUBLIC_MASTER_KEY_SIZE);
	public_signing_key->key.len = PUBLIC_MASTER_KEY_SIZE;
	private_signing_key->key.data = throwing_zeroed_malloc<uint8_t>(PRIVATE_MASTER_KEY_SIZE);
	private_signing_key->key.len = PRIVATE_MASTER_KEY_SIZE;
	public_identity_key->key.data = throwing_zeroed_malloc<uint8_t>(PUBLIC_KEY_SIZE);
	public_identity_key->key.len = PUBLIC_KEY_SIZE;
	private_identity_key->key.data = throwing_zeroed_malloc<uint8_t>(PRIVATE_KEY_SIZE);
	private_identity_key->key.len = PRIVATE_KEY_SIZE;

	//copy the keys
	if (this->public_signing_key.cloneToRaw(public_signing_key->key.data, PUBLIC_MASTER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to export public signing key.");
	}
	if (this->public_identity_key.cloneToRaw(public_identity_key->key.data, PUBLIC_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to export public identity key.");
	}
	Unlocker unlocker(*this);
	if (this->private_signing_key.cloneToRaw(private_signing_key->key.data, PRIVATE_MASTER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to export private signing key.");
	}
	if (this->private_identity_key.cloneToRaw(private_identity_key->key.data, PRIVATE_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to export private identity key.");
	}
}

void MasterKeys::lock() const {
	int status = sodium_mprotect_noaccess(this->private_keys.get());
	if (status != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to lock memory.");
	}
}

void MasterKeys::unlock() const {
	int status = sodium_mprotect_readonly(this->private_keys.get());
	if (status != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to make memory readonly.");
	}
}

void MasterKeys::unlock_readwrite() const {
	int status = sodium_mprotect_readwrite(this->private_keys.get());
	if (status != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to make memory readwrite.");
	}
}

std::ostream& MasterKeys::print(std::ostream& stream) const {
	Unlocker unlocker(*this);

	stream << "Public Signing Key:\n";
	stream << this->public_signing_key.toHex() << '\n';
	stream << "Private Signing Key:\n";
	stream << this->private_signing_key.toHex() << '\n';
	stream << "Public Identity Key:\n";
	stream << this->public_identity_key.toHex() << '\n';
	stream << "Private Identity Key:\n";
	stream << this->private_identity_key.toHex() << '\n';

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
