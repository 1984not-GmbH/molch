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

#ifndef LIB_MASTER_KEYS
#define LIB_MASTER_KEYS

#include <memory>
#include <ostream>

#include "constants.h"
#include "buffer.hpp"
#include "return-status.hpp"
#include "sodium-wrappers.hpp"
#include "protobuf.hpp"
#include "key.hpp"
#include "gsl.hpp"

namespace Molch {
	class PrivateMasterKeyStorage {
		friend class MasterKeys;
		PrivateSigningKey signing_key;
		PrivateKey identity_key;
	};

	class MasterKeys {
	private:
		mutable std::unique_ptr<PrivateMasterKeyStorage,SodiumDeleter<PrivateMasterKeyStorage>> private_keys;
		//Ed25519 key for signing
		PublicSigningKey public_signing_key;
		PrivateSigningKey *private_signing_key{nullptr};
		//X25519 key for deriving axolotl root keys
		PublicKey public_identity_key;
		PrivateKey *private_identity_key{nullptr};

		/* Internally does the intialization of the buffers creation of the keys */
		void init();
		result<void> generate() noexcept;
		result<void> generate(const span<const std::byte> low_entropy_seed) noexcept;

		/* Manage the memory for the private keys */
		void lock() const noexcept;
		void unlock() const noexcept;
		void unlock_readwrite() const noexcept;

		class ReadWriteUnlocker {
		private:
			const MasterKeys& keys;
		public:
			ReadWriteUnlocker(const MasterKeys& keys) noexcept;
			~ReadWriteUnlocker() noexcept;
		};

		MasterKeys& move(MasterKeys&& master_keys) noexcept;

	public:
		/*
		 * Create a new set of master keys.
		 *
		 * Optionally wit a seed. It can be of any length and doesn't
		 * require to have high entropy. It will be used as entropy source
		 * in addition to the OSs CPRNG.
		 *
		 * WARNING: Don't use Entropy from the OSs CPRNG as seed!
		 */
		MasterKeys();
		MasterKeys(const span<const std::byte> low_entropy_seed);

		/*
		 * import from Protobuf-C
		 */
		MasterKeys(
			const ProtobufCKey& public_signing_key,
			const ProtobufCKey& private_signing_key,
			const ProtobufCKey& public_identity_key,
			const ProtobufCKey& private_identity_key);

		MasterKeys(const MasterKeys& master_keys) = delete;
		MasterKeys(MasterKeys&& master_keys) noexcept;

		MasterKeys& operator=(const MasterKeys& master_keys) = delete;
		MasterKeys& operator=(MasterKeys&& master_keys) noexcept;

		const PublicSigningKey& getSigningKey() const noexcept;
		result<const PrivateSigningKey*> getPrivateSigningKey() const noexcept;
		const PublicKey& getIdentityKey() const noexcept;
		result<const PrivateKey*> getPrivateIdentityKey() const noexcept;

		/*
		 * Sign a piece of data. Returns the data and signature in one output buffer.
		 */
		result<Buffer> sign(const span<const std::byte> data) const; //output, length of data + SIGNATURE_SIZE

		/*! Export a set of master keys into a user Protobuf-C struct
		 * \param public_signing_key Public pasrt of the signing keypair.
		 * \param private_signing_key Private part of the signing keypair.
		 * \param public_identity_key Public part of the identity keypair.
		 * \param private_identity_key Private part of the idenity keypair.
		 */
		void exportProtobuf(
				Arena& arena,
				ProtobufCKey*& public_signing_key,
				ProtobufCKey*& private_signing_key,
				ProtobufCKey*& public_identity_key,
				ProtobufCKey*& private_identity_key) const;

		/*! Readonly unlocks the private keys when created and
		 * automatically locks them if destroyed.
		 */
		class Unlocker {
		private:
			const MasterKeys& keys;
		public:
			Unlocker(const MasterKeys& keys) noexcept;
			~Unlocker() noexcept;
		};

		std::ostream& print(std::ostream& stream) const;
	};
}

#endif
