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

#ifndef LIB_PrekeyStore
#define LIB_PrekeyStore

#include <memory>
#include <array>
#include <vector>
#include <ostream>

#include "constants.h"
#include "buffer.hpp"
#include "return-status.hpp"
#include "protobuf.hpp"
#include "sodium-wrappers.hpp"
#include "key.hpp"
#include "gsl.hpp"
#include "time.hpp"
#include "protobuf-arena.hpp"

namespace Molch {
	class Prekey {
		friend class PrekeyStore;
	private:
		void fill(const PublicKey& public_key, const PrivateKey& private_key, const seconds expiration_date) noexcept;
		result<void> generate() noexcept;

		Prekey& copy(const Prekey& node) noexcept;
		Prekey& move(Prekey&& node) noexcept;

		PublicKey public_key;
		PrivateKey private_key;
		seconds expiration_date{0};

	public:
		Prekey() = default;
		Prekey(const PublicKey& public_key, const PrivateKey& private_key, seconds expiration_date) noexcept;
		/* copy constructor */
		Prekey(const Prekey& node) noexcept;
		/* move constructor */
		Prekey(Prekey&& node) noexcept;

		static result<Prekey> import(const ProtobufCPrekey& keypair);

		/* copy assignment */
		Prekey& operator=(const Prekey& node) noexcept;
		/* move assignment */
		Prekey& operator=(Prekey&& node) noexcept;

		seconds expirationDate() const noexcept;
		const PublicKey& publicKey() const noexcept;
		const PrivateKey& privateKey() const noexcept;

		result<ProtobufCPrekey*> exportProtobuf(Arena& arena) const;

		std::ostream& print(std::ostream& stream) const;
	};

	class PrekeyStore {
	private:
		seconds oldest_expiration_date{0};
		seconds oldest_deprecated_expiration_date{0};

		void init();
		result<void> generateKeys();

		void updateExpirationDate() noexcept;
		void updateDeprecatedExpirationDate() noexcept;

		/*
		 * Helper that puts a prekey pair in the deprecated list and generates a new one.
		 */
		result<void> deprecate(const size_t index);

		std::unique_ptr<std::array<Prekey,PREKEY_AMOUNT>,SodiumDeleter<std::array<Prekey,PREKEY_AMOUNT>>> prekeys_storage;
		std::vector<Prekey,SodiumAllocator<Prekey>> deprecated_prekeys_storage;

	public:

		PrekeyStore() = delete;
		PrekeyStore(uninitialized_t uninitialized);

		/*
		 * Create a new keystore. Generates all the keys.
		 */
		static result<PrekeyStore> create();

		/*! Import a prekey store from a protobuf-c struct.
		 * \param keypairs An array of prekey pairs.
		 * \param deprecated_keypairs An array of deprecated prekey pairs.
		 *
		 * \return The imported PrekeyStore
		 */
		static result<PrekeyStore> import(
				const span<ProtobufCPrekey*> keypairs,
				const span<ProtobufCPrekey*> deprecated_keypairs);

		/*
		 * Get a private prekey from it's public key. This will automatically
		 * deprecate the requested prekey put it in the outdated key store and
		 * generate a new one.
		 */
		result<PrivateKey> getPrekey(const PublicKey& public_key);

		/*
		 * Generate a list containing all public prekeys.
		 * (this list can then be stored on a public server).
		 */
		result<Buffer> list() const; //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

		/*
		 * Automatically deprecate old keys and generate new ones
		 * and THROW away deprecated ones that are too old.
		 */
		result<void> rotate();

		struct ExportedPrekeyStore {
			span<ProtobufCPrekey*> keypairs;
			span<ProtobufCPrekey*> deprecated_keypairs;
		};

		/*! Serialise a prekey store as protobuf-c struct.
		 * \param arena A memory arena to allocate from.
		 *
		 * \return Spans pointing inside the arena containing the exported prekey store.
		 */
		result<ExportedPrekeyStore> exportProtobuf(Arena& arena) const;

		const std::array<Prekey,PREKEY_AMOUNT>& prekeys() const noexcept;
		const std::vector<Prekey,SodiumAllocator<Prekey>>& deprecatedPrekeys() const noexcept;
		const seconds& oldestExpirationDate() const noexcept;
		const seconds& oldestDeprecatedExpirationDate() const noexcept;

		std::ostream& print(std::ostream& stream) const;

		//DON'T USE, THIS IS ONLY FOR TESTING!
		result<void> timeshiftForTestingOnly(size_t index, seconds timeshift);
		void timeshiftDeprecatedForTestingOnly(size_t index, seconds timeshift) noexcept;
	};
}
#endif
