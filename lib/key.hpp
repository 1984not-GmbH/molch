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
#include "exception.hpp"
#include "endianness.hpp"
#include "gsl.hpp"
#include "protobuf.hpp"
#include "protobuf-arena.hpp"
#include "copy.hpp"

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
		PrivateSigningKey,
		ConversationId,
	};

	template <size_t key_length, KeyType keytype>
	class Key : public std::array<std::byte,key_length> {
	private:
		Key& copy(const Key& key) noexcept {
			std::copy(std::cbegin(key), std::cend(key), std::begin(*this));

			return *this;
		}

		Key& move(Key&& key) noexcept {
			return this->copy(key);
		}

	public:
		static constexpr size_t length{key_length};

		Key(uninitialized_t uninitialized) noexcept {
			(void)uninitialized;
		}

		Key() noexcept {
			this->zero();
		}

		Key(const Key& key) noexcept {
			this->copy(key);
		}

		Key(Key&& key) noexcept {
			this->move(std::move(key));
		}

		static result<Key> import(const ProtobufCKey& key) noexcept {
			Key imported_key(uninitialized_t::uninitialized);
			OUTCOME_TRY(copyFromTo({key.key}, imported_key));
			return imported_key;
		}

		static result<Key> fromSpan(const span<const std::byte>& key) noexcept {
			Key imported_key(uninitialized_t::uninitialized);
			OUTCOME_TRY(copyFromTo(key, imported_key));
			return imported_key;
		}

		~Key() noexcept {
			this->zero();
		}

		Key& operator=(const Key& key) noexcept {
			return this->copy(key);
		}
		Key& operator=(Key&& key) noexcept {
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
		int compare(const Key& key) const noexcept {
			auto comparison{sodium_compare(*this, key)};
			if (!comparison) {
				//This can never happen because *this and key have the same length
				std::terminate();
			}
			return comparison.value();
		}

		//comparison operators
		bool operator>(const Key& key) const noexcept {
			return (this->compare(key) == 1);
		}
		bool operator<(const Key& key) const noexcept {
			return (this->compare(key) == -1);
		}
		bool operator>=(const Key& key) const noexcept {
			return !(*this < key);
		}
		bool operator<=(const Key& key) const noexcept {
			return !(*this > key);
		}
		bool operator==(const Key& key) const noexcept {
			return (this->compare(key) == 0);
		}
		bool operator!=(const Key& key) const noexcept {
			return !(*this == key);
		}

		template <typename DerivedKeyType>
		result<DerivedKeyType> deriveSubkeyWithIndex(const uint32_t subkey_counter) const {
			DerivedKeyType derived_key;
			static_assert(DerivedKeyType::length <= crypto_generichash_blake2b_BYTES_MAX, "The derived length is greater than crypto_generichas_blake2b_BYTES_MAX");
			static_assert(DerivedKeyType::length >= crypto_generichash_blake2b_BYTES_MIN, "The derived length is smaller than crypto_generichash_blake2b_BYTES_MAX");
			static_assert(length <= crypto_generichash_blake2b_KEYBYTES_MAX, "The length to derive from is greater than crypto_generichash_blake2b_KEYBYTES_MAX");
			static_assert(length >= crypto_generichash_blake2b_KEYBYTES_MIN, "The length to derive from is smaller than crypto_generichash_blake2b_KEYBYTES_MIN");

			//create a salt that contains the number of the subkey
			auto salt{Key<crypto_generichash_blake2b_SALTBYTES,KeyType::Key>()};
			//fill the salt with a big endian representation of the subkey counter
			TRY_VOID(to_big_endian(subkey_counter, {salt.data()+ salt.size() - sizeof(uint32_t), sizeof(uint32_t)}));

			const unsigned char personal[]{"molch_cryptolib"};
			static_assert(sizeof(personal) == crypto_generichash_blake2b_PERSONALBYTES, "personal string is not crypto_generichash_blake2b_PERSONALBYTES long");

			//set length of output
			TRY_VOID(crypto_generichash_blake2b_salt_personal(
					derived_key,
					{nullptr, static_cast<size_t>(0)}, //input
					*this,
					salt,
					{uchar_to_byte(personal), sizeof(personal)}));

			return derived_key;
		}

		void zero() noexcept {
			sodium_memzero(*this);
		}

		result<ProtobufCKey*> exportProtobuf(Arena& arena) const noexcept {
			auto key{arena.allocate<ProtobufCKey>(1)};
			molch__protobuf__key__init(key);

			key->key.data = arena.allocate<uint8_t>(length);
			key->key.len = length;
			OUTCOME_TRY(copyFromTo(*this, {uchar_to_byte(key->key.data), key->key.len}));

			return key;
		}
	};


	template <size_t key_length, KeyType keytype>
	class EmptyableKey : public std::array<std::byte,key_length> {
	private:
		EmptyableKey& copy(const EmptyableKey& key) noexcept {
			this->empty = key.empty;

			std::copy(std::cbegin(key), std::cend(key), std::begin(*this));

			return *this;
		}

		EmptyableKey& move(EmptyableKey&& key) noexcept {
			this->empty = key.empty;

			if (key.empty) {
				key.zero();
				return *this;
			}

			return this->copy(key);
		}

	public:
		static constexpr size_t length{key_length};

		bool empty{true};

		EmptyableKey() = default;
		EmptyableKey(const EmptyableKey& key) noexcept {
			this->copy(key);
		}

		EmptyableKey(EmptyableKey&& key) noexcept {
			this->move(std::move(key));
		}

		EmptyableKey(const Key<key_length,keytype>& key) noexcept : empty{false} {
			std::copy(std::cbegin(key), std::cend(key), std::begin(*this));
		}

		~EmptyableKey() noexcept {
			this->zero();
		}

		EmptyableKey& operator=(const EmptyableKey& key) noexcept {
			return this->copy(key);
		}
		EmptyableKey& operator=(EmptyableKey&& key) noexcept {
			return this->move(std::move(key));
		}

		static result<EmptyableKey> fromSpan(const span<const std::byte> other) {
			EmptyableKey<key_length,keytype> key;
			key.empty = false;
			OUTCOME_TRY(copyFromTo(other, key));
			return key;
		}

		static result<EmptyableKey> import(const ProtobufCKey& key) {
			EmptyableKey<key_length,keytype> imported_key;
			imported_key.empty = false;
			OUTCOME_TRY(copyFromTo({key.key}, imported_key));
			return imported_key;
		}

		/*
		 * Constant time comparison of two keys.
		 *
		 * returns:
		 *  -2 if one of the keys is empty
		 *  -1 if this is less than key
		 *   0 if this is equal to key
		 *  +1 if this is greater than key
		 *
		 *  throws an exception if either is empty.
		 */
		int compare(const EmptyableKey& key) const noexcept {
			if (this->empty || key.empty) {
				return -2;
			}

			auto comparison{sodium_compare(*this, key)};
			if (!comparison) {
				//This can never happen because *this and key have the same length
				std::terminate();
			}
			return comparison.value();
		}

		//comparison operators
		bool operator>(const EmptyableKey& key) const noexcept {
			return (this->compare(key) == 1);
		}
		bool operator<(const EmptyableKey& key) const noexcept {
			return (this->compare(key) == -1);
		}
		bool operator>=(const EmptyableKey& key) const noexcept {
			return !(*this < key);
		}
		bool operator<=(const EmptyableKey& key) const noexcept {
			return !(*this > key);
		}
		bool operator==(const EmptyableKey& key) const noexcept {
			if (this->empty && key.empty) { //TODO remove eventually
				return true;
			}

			return (this->compare(key) == 0);
		}
		bool operator!=(const EmptyableKey& key) const noexcept {
			return !(*this == key);
		}

		template <typename DerivedKeyType>
		result<DerivedKeyType> deriveSubkeyWithIndex(const uint32_t subkey_counter) const {
			FulfillOrFail(!this->empty);

			DerivedKeyType derived_key;
			derived_key.empty = false;
			static_assert(DerivedKeyType::length <= crypto_generichash_blake2b_BYTES_MAX, "The derived length is greater than crypto_generichas_blake2b_BYTES_MAX");
			static_assert(DerivedKeyType::length >= crypto_generichash_blake2b_BYTES_MIN, "The derived length is smaller than crypto_generichash_blake2b_BYTES_MAX");
			static_assert(length <= crypto_generichash_blake2b_KEYBYTES_MAX, "The length to derive from is greater than crypto_generichash_blake2b_KEYBYTES_MAX");
			static_assert(length >= crypto_generichash_blake2b_KEYBYTES_MIN, "The length to derive from is smaller than crypto_generichash_blake2b_KEYBYTES_MIN");

			//create a salt that contains the number of the subkey
			EmptyableKey<crypto_generichash_blake2b_SALTBYTES,KeyType::Key> salt;
			salt.zero(); //fill with zeroes

			//fill the salt with a big endian representation of the subkey counter
			TRY_VOID(to_big_endian(subkey_counter, {salt.data()+ salt.size() - sizeof(uint32_t), sizeof(uint32_t)}));

			const unsigned char personal[]{"molch_cryptolib"};
			static_assert(sizeof(personal) == crypto_generichash_blake2b_PERSONALBYTES, "personal string is not crypto_generichash_blake2b_PERSONALBYTES long");

			//set length of output
			TRY_VOID(crypto_generichash_blake2b_salt_personal(
					derived_key,
					{nullptr, static_cast<size_t>(0)}, //input
					*this,
					salt,
					{uchar_to_byte(personal), sizeof(personal)}));

			return derived_key;
		}

		std::optional<Key<key_length,keytype>> toKey() const noexcept {
			if (this->empty) {
				return std::nullopt;
			}

			Key<key_length,keytype> key(uninitialized_t::uninitialized);
			std::copy(std::cbegin(*this), std::cend(*this), std::begin(key));

			return key;
		}

		//TODO get rid of this
		bool isNone() const noexcept {
			if (this->empty) {
				return true;
			}

			return sodium_is_zero(*this);
		}

		void clearKey() noexcept {
			this->zero();
			this->empty = true;
		}

		void zero() noexcept {
			sodium_memzero(*this);
		}

		result<ProtobufCKey*> exportProtobuf(Arena& arena) const noexcept {
			auto key{arena.allocate<ProtobufCKey>(1)};
			molch__protobuf__key__init(key);

			key->key.data = arena.allocate<uint8_t>(length);
			key->key.len = length;
			OUTCOME_TRY(copyFromTo(*this, {uchar_to_byte(key->key.data), key->key.len}));

			return key;
		}
	};

	template <size_t key_length,KeyType keytype>
	std::ostream& operator<<(std::ostream& stream, const EmptyableKey<key_length,keytype> key) {
		static constexpr size_t width{30};

		if (key.empty) {
			return stream << "(empty)";
		}

		const size_t hex_length{key.size() * 2 + sizeof("")};
		auto hex{std::make_unique<char[]>(hex_length)};
		TRY_VOID(sodium_bin2hex({hex.get(), hex_length}, key));

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

	using MessageKey = Key<MESSAGE_KEY_SIZE,KeyType::MessageKey>;

	class EmptyableChainKey : public EmptyableKey<CHAIN_KEY_SIZE,KeyType::ChainKey> {
	public:
		//inherit constructors
		using EmptyableKey<CHAIN_KEY_SIZE,KeyType::ChainKey>::EmptyableKey;

		static result<EmptyableChainKey> fromSpan(const span<const std::byte> input) {
			EmptyableChainKey key;
			key.empty = false;
			OUTCOME_TRY(copyFromTo(input, key));
			return key;
		}

		result<MessageKey> deriveMessageKey() const noexcept {
			OUTCOME_TRY(subkey, this->deriveSubkeyWithIndex<EmptyableKey<MESSAGE_KEY_SIZE,KeyType::MessageKey>>(0));
			return subkey.toKey().value(); //this will never be empty
		}

		result<EmptyableChainKey> deriveChainKey() const noexcept {
			return this->deriveSubkeyWithIndex<EmptyableChainKey>(1);
		}
	};

	class ChainKey : public Key<CHAIN_KEY_SIZE,KeyType::ChainKey> {
	public:
		//inherit constructors
		using Key<CHAIN_KEY_SIZE,KeyType::ChainKey>::Key;

		static result<ChainKey> fromSpan(const span<const std::byte> input) {
			ChainKey key;
			OUTCOME_TRY(copyFromTo(input, key));
			return key;
		}

		result<MessageKey> deriveMessageKey() const noexcept {
			OUTCOME_TRY(subkey, this->deriveSubkeyWithIndex<EmptyableKey<MESSAGE_KEY_SIZE,KeyType::MessageKey>>(0));
			return subkey.toKey().value(); //this will never be empty
		}

		result<ChainKey> deriveChainKey() const noexcept {
			return this->deriveSubkeyWithIndex<ChainKey>(1);
		}
	};

	template <size_t key_length,KeyType key_type>
	std::ostream& operator<<(std::ostream& stream, Key<key_length,key_type> key) noexcept {
		const size_t hex_length{key.size() * 2 + sizeof("")};
		auto hex{std::make_unique<char[]>(hex_length)};
		if (not sodium_bin2hex({hex.get(), hex_length}, key).has_value()) {
			// This can't happen
			std::terminate();
		}

		static constexpr size_t width{30};
		for (size_t i{0}; i < hex_length; i++) {
			if (((i % width) == 0) && (i != 0)) {
				stream << '\n';
			} else if ((i % 2 == 0) && (i != 0)) {
				stream << ' ';
			}
			stream << hex[i];
		}

		return stream;
	}

	using EmptyableHeaderKey = EmptyableKey<HEADER_KEY_SIZE,KeyType::HeaderKey>;
	using EmptyableRootKey = EmptyableKey<ROOT_KEY_SIZE,KeyType::RootKey>;

	using HeaderKey = Key<HEADER_KEY_SIZE,KeyType::HeaderKey>;
	using RootKey = Key<ROOT_KEY_SIZE,KeyType::RootKey>;
	using BackupKey = Key<BACKUP_KEY_SIZE,KeyType::BackupKey>;
	using PublicKey = Key<PUBLIC_KEY_SIZE,KeyType::PublicKey>;
	using PrivateKey = Key<PRIVATE_KEY_SIZE,KeyType::PrivateKey>;
	using PublicSigningKey = Key<PUBLIC_MASTER_KEY_SIZE,KeyType::PublicSigningKey>;
	using PrivateSigningKey = Key<PRIVATE_MASTER_KEY_SIZE,KeyType::PrivateSigningKey>;
	using ConversationId = Key<CONVERSATION_ID_SIZE,KeyType::ConversationId>;
}

#endif /* LIB_KEY_HPP */
