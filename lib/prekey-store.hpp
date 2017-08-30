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

#include <ctime>
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
#include "protobuf-pool.hpp"
#include "gsl.hpp"

namespace Molch {
	class Prekey {
		friend class PrekeyStore;
	private:
		void fill(const PublicKey& public_key, const PrivateKey& private_key, const int64_t expiration_date);
		void generate();

		Prekey& copy(const Prekey& node);
		Prekey& move(Prekey&& node);

	public:
		PublicKey public_key;
		PrivateKey private_key;
		int64_t expiration_date{0};

		Prekey() = default;
		Prekey(const PublicKey& public_key, const PrivateKey& private_key, int64_t expiration_date);
		/* copy constructor */
		Prekey(const Prekey& node);
		/* move constructor */
		Prekey(Prekey&& node);
		Prekey(const ProtobufCPrekey& keypair);

		/* copy assignment */
		Prekey& operator=(const Prekey& node);
		/* move assignment */
		Prekey& operator=(Prekey&& node);

		ProtobufCPrekey* exportProtobuf(ProtobufPool& pool) const;

		std::ostream& print(std::ostream& stream) const;
	};

	class PrekeyStore {
	private:
		void init();
		void generateKeys();

		void updateExpirationDate();
		void updateDeprecatedExpirationDate();

		/*
		 * Helper that puts a prekey pair in the deprecated list and generates a new one.
		 */
		void deprecate(const size_t index);

	public:
		int64_t oldest_expiration_date{0};
		int64_t oldest_deprecated_expiration_date{0};
		std::unique_ptr<std::array<Prekey,PREKEY_AMOUNT>,SodiumDeleter<std::array<Prekey,PREKEY_AMOUNT>>> prekeys;
		std::vector<Prekey,SodiumAllocator<Prekey>> deprecated_prekeys;

		/*
		 * Initialise a new keystore. Generates all the keys.
		 */
		PrekeyStore();

		/*! Import a prekey store from a protobuf-c struct.
		 * \param keypairs An array of prekeys pairs.
		 * \param keypais_length The length of the array of prekey pairs.
		 * \param deprecated_keypairs An array of deprecated prekey pairs.
		 * \param deprecated_keypairs_length The length of the array of deprecated prekey pairs.
		 * \returns The status.
		 */
		PrekeyStore(
				const gsl::span<ProtobufCPrekey*> keypairs,
				const gsl::span<ProtobufCPrekey*> deprecated_keypairs);

		/*
		 * Get a private prekey from it's public key. This will automatically
		 * deprecate the requested prekey put it in the outdated key store and
		 * generate a new one.
		 */
		void getPrekey(const PublicKey& public_key, PrivateKey& private_key);

		/*
		 * Generate a list containing all public prekeys.
		 * (this list can then be stored on a public server).
		 */
		void list(gsl::span<gsl::byte> list) const; //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

		/*
		 * Automatically deprecate old keys and generate new ones
		 * and THROW away deprecated ones that are too old.
		 */
		void rotate();

		/*! Serialise a prekey store as protobuf-c struct.
		 * \param keypairs An array of keypairs, allocated by the function.
		 * \param keypairs_length The length of the array of keypairs.
		 * \param deprecated_keypairs An array of deprecated keypairs, allocated by the function.
		 * \param deprecated_keypairs_length The length of the array of deprecated keypairs.
		 */
		void exportProtobuf(
				ProtobufPool& pool,
				gsl::span<ProtobufCPrekey*>& keypairs,
				gsl::span<ProtobufCPrekey*>& deprecated_keypairs) const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif
