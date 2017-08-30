/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 Max Bruckner (FSMaxB) <max at maxbruckner dot de>
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

#ifndef LIB_KEY_HPP
#define LIB_KEY_HPP

#include <array>
#include <memory>
#include <ostream>
#include <sodium.h>
#include <iterator>
#include <algorithm>

#include "buffer.hpp"
#include "constants.h"
#include "molch-exception.hpp"
#include "endianness.hpp"
#include "gsl.hpp"

namespace Molch {

	//type of key, this is used to distinguish key types
	//and for example avoid copying a private key to a public key
	enum class KeyType : uint8_t {
		Key,
		MessageKey,
		ChainKey,
		HeaderKey,
		RootKey,
		BackupKey,
		PublicKey,
		PrivateKey,
		PublicSigningKey,
		PrivateSigningKey
	};

	template <size_t length, KeyType keytype>
	class Key : public std::array<gsl::byte,length> {
	private:
		Key& copy(const Key& key) {
			this->empty = key.empty;

			std::copy(std::cbegin(key), std::cend(key), std::begin(*this));

			return *this;
		}

		Key& move(Key&& key) {
			this->empty = key.empty;

			if (key.empty) {
				key.clear();
				return *this;
			}

			for (size_t i{0}; i < length; ++i) {
				(*this)[i] = key[i];
			}

			return *this;
		}

	public:
		bool empty{true};

		Key() = default;
		Key(const Key& key) {
			this->copy(key);
		}

		Key(Key&& key) {
			this->move(std::move(key));
		}

		~Key() {
			this->clear();
		}

		Key& operator=(const Key& key) {
			return this->copy(key);
		}
		Key& operator=(Key&& key) {
			return this->move(std::move(key));
		}

		/*
		 * Constant time comparison of two keys.
		 *
		 * returns:
		 *  -1 if this is less than key
		 *   0 if this is equal to key
		 *  +1 if this is greater than key
		 *
		 *  throws an exception if either is empty.
		 */
		int compare(const Key& key) const {
			Expects(!this->empty && !key.empty);

			return sodium_compare(
					byte_to_uchar(this->data()),
					byte_to_uchar(key.data()),
					length);
		}

		//comparison operators
		bool operator>(const Key& key) const {
			return (this->compare(key) == 1);
		}
		bool operator<(const Key& key) const {
			return (this->compare(key) == -1);
		}
		bool operator>=(const Key& key) const {
			return !(*this < key);
		}
		bool operator<=(const Key& key) const {
			return !(*this > key);
		}
		bool operator==(const Key& key) const {
			if (this->empty && key.empty) {
				return true;
			} else if (this->empty || key.empty) {
				return false;
			}

			return (this->compare(key) == 0);
		}
		bool operator!=(const Key& key) const {
			return !(*this == key);
		}

		KeyType type() {
			return type;
		}

		template <size_t derived_length,KeyType derived_type>
		void deriveTo(Key<derived_length,derived_type>& derived_key, const uint32_t subkey_counter) const {
			Expects(!this->empty);

			static_assert(derived_length <= crypto_generichash_blake2b_BYTES_MAX, "The derived length is greater than crypto_generichas_blake2b_BYTES_MAX");
			static_assert(derived_length >= crypto_generichash_blake2b_BYTES_MIN, "The derived length is smaller than crypto_generichash_blake2b_BYTES_MAX");
			static_assert(length <= crypto_generichash_blake2b_KEYBYTES_MAX, "The length to derive from is greater than crypto_generichash_blake2b_KEYBYTES_MAX");
			static_assert(length >= crypto_generichash_blake2b_KEYBYTES_MIN, "The length to derive from is smaller than crypto_generichash_blake2b_KEYBYTES_MIN");

			//create a salt that contains the number of the subkey
			Key<crypto_generichash_blake2b_SALTBYTES,KeyType::Key> salt;
			salt.clear(); //fill with zeroes
			salt.empty = false;

			//fill the salt with a big endian representation of the subkey counter
			to_big_endian(subkey_counter, {salt.data()+ salt.size() - sizeof(uint32_t), sizeof(uint32_t)});

			const unsigned char personal[]{"molch_cryptolib"};
			static_assert(sizeof(personal) == crypto_generichash_blake2b_PERSONALBYTES, "personal string is not crypto_generichash_blake2b_PERSONALBYTES long");

			//set length of output
			auto status{crypto_generichash_blake2b_salt_personal(
					byte_to_uchar(derived_key.data()),
					derived_length,
					nullptr, //input
					0, //input length
					byte_to_uchar(this->data()),
					length,
					byte_to_uchar(salt.data()),
					personal)};
			if (status != 0) {
				throw Exception{status_type::KEYDERIVATION_FAILED, "Failed to derive key via crypto_generichash_blake2b_salt_personal"};
			}

			derived_key.empty = false;
		}

		gsl::span<gsl::byte> span() {
			return {this->data(), length};
		}

		const gsl::span<const gsl::byte> span() const {
			return {this->data(), length};
		}

		void fillRandom() {
			randombytes_buf(reinterpret_cast<void*>(this->data()), this->size());
			this->empty = false;
		}

		//TODO get rid of this
		bool isNone() const {
			if (this->empty) {
				return true;
			}

			return sodium_is_zero(byte_to_uchar(this->data()), length);
		}

		//copy from a raw byte array
		void set(const gsl::span<const gsl::byte> data) {
			Expects(data.size() == length);

			std::copy(std::cbegin(data), std::cend(data), this->data());
			this->empty = false;
		}

		//copy to a raw byte array
		void copyTo(gsl::span<gsl::byte> data) const {
			Expects(data.size() == length);

			std::copy(std::cbegin(*this), std::cend(*this), std::begin(data));
		}

		void clear() {
			sodium_memzero(reinterpret_cast<void*>(this->data()), length);
			this->empty = true;
		}

		std::ostream& printHex(std::ostream& stream) const {
			static constexpr size_t width{30};

			if (this->empty) {
				return stream << "(empty)";
			}

			const size_t hex_length{this->size() * 2 + sizeof("")};
			auto hex{std::make_unique<char[]>(hex_length)};
			if (sodium_bin2hex(hex.get(), hex_length, byte_to_uchar(this->data()), this->size()) == nullptr) {
				throw Exception{status_type::BUFFER_ERROR, "Failed to converst binary to hex with sodium_bin2hex."};
			}

			for (size_t i{0}; i < hex_length; i++) {
				if ((width != 0) && ((i % width) == 0) && (i != 0)) {
					stream << '\n';
				} else if ((i % 2 == 0) && (i != 0)) {
					stream << ' ';
				}
				stream << hex[i];
			}

			return stream;
		}
	};

	class MessageKey : public Key<MESSAGE_KEY_SIZE,KeyType::MessageKey> {
	};

	class ChainKey : public Key<CHAIN_KEY_SIZE,KeyType::ChainKey> {
	public:
		MessageKey deriveMessageKey() const {
			MessageKey message_key;
			this->deriveTo(message_key, 0);

			return message_key;
		}

		ChainKey deriveChainKey() const {
			ChainKey chain_key;
			this->deriveTo(chain_key, 1);

			return chain_key;
		}
	};

	class HeaderKey : public Key<HEADER_KEY_SIZE,KeyType::HeaderKey> {};

	class RootKey : public Key<ROOT_KEY_SIZE,KeyType::RootKey> {};

	class BackupKey : public Key<BACKUP_KEY_SIZE,KeyType::BackupKey> {};

	class PublicKey : public Key<PUBLIC_KEY_SIZE,KeyType::PublicKey> {};
	class PrivateKey : public Key<PRIVATE_KEY_SIZE,KeyType::PrivateKey> {};

	class PublicSigningKey : public Key<PUBLIC_MASTER_KEY_SIZE,KeyType::PublicSigningKey> {};
	class PrivateSigningKey : public Key<PRIVATE_MASTER_KEY_SIZE,KeyType::PrivateSigningKey> {};
}

#endif /* LIB_KEY_HPP */
