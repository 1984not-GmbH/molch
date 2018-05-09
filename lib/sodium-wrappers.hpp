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

#ifndef LIB_SODIUM_WRAPPERS_H
#define LIB_SODIUM_WRAPPERS_H

#include <sodium.h>
#include <memory>
#include <limits>

#include "gsl.hpp"
#include "constants.h"

namespace Molch {
	/*
	 * Calls sodium_malloc and throws std::bad_alloc if allocation fails
	 */
	template <typename T>
	T* sodium_malloc(size_t elements) {
		if (elements == 0) {
			throw std::bad_alloc();
		}

		//check for overflow
		if ((std::numeric_limits<size_t>::max() / elements) < sizeof(T)) {
			throw std::bad_alloc();
		}

		auto memory{::sodium_malloc(elements * sizeof(T))};
		if (memory == nullptr) {
			throw std::bad_alloc();
		}

		return reinterpret_cast<T*>(memory);
	}

	template <class T>
	class SodiumAllocator {
	public:
		using value_type = T;

		SodiumAllocator() = default;
		template <class U>
		constexpr SodiumAllocator(const SodiumAllocator<U>&) noexcept {}

		T* allocate(size_t elements, const T* hint = nullptr) {
			(void)hint;
			return sodium_malloc<T>(elements);
		}
		void deallocate(T* pointer, size_t elements) noexcept {
			(void)elements;
			sodium_free(pointer);
		}
	};
	template <class T, class U>
	bool operator==(const SodiumAllocator<T>&, const SodiumAllocator<U>&) {
		return true;
	}
	template <class T, class U>
	bool operator!=(const SodiumAllocator<T>&, const SodiumAllocator<U>&) {
		return false;
	}

	template <typename T>
	class SodiumDeleter {
	public:
		void operator()(T* object) {
			if (object != nullptr) {
				sodium_free(object);
			}
		}
	};

	void sodium_init();

	void crypto_box_keypair(const span<std::byte> public_key, const span<std::byte> private_key);
	void crypto_box_seed_keypair(const span<std::byte> public_key, const span<std::byte> private_key, const span<const std::byte> seed);

	void crypto_sign_keypair(const span<std::byte> public_key, const span<std::byte> private_key);
	void crypto_sign_seed_keypair(const span<std::byte> public_key, const span<std::byte> private_key, const span<const std::byte> seed);

	void crypto_generichash(const span<std::byte> output, const span<const std::byte> input, const span<const std::byte> key);

	struct CryptoGenerichash {
		crypto_generichash_state state;
		const size_t output_length;

		CryptoGenerichash(const span<const std::byte> key, size_t output_length);

		void update(const span<const std::byte> input);
		void final(const span<std::byte> output);

		~CryptoGenerichash();
	};

	void crypto_generichash_blake2b_salt_personal(
			const span<std::byte> output,
			const span<const std::byte> input,
			const span<const std::byte> key,
			const span<const std::byte> salt,
			const span<const std::byte> personal);

	void randombytes_buf(const span<std::byte> buffer);

	void crypto_pwhash(
			const span<std::byte> output,
			const span<const std::byte> password,
			const span<const std::byte> salt,
			unsigned long long opslimit,
			size_t memlimit,
			int algorithm);

	//TODO find out how to use PublicKey and PrivateKey as parameters here
	void crypto_scalarmult_base(const span<std::byte> public_key, const span<const std::byte> private_key);

	void crypto_scalarmult(
			const span<std::byte> shared_secret,
			const span<const std::byte> our_private_key,
			const span<const std::byte> their_public_key);

	bool sodium_is_zero(const span<const std::byte> buffer);

	bool sodium_memcmp(const span<const std::byte> b1, const span<const std::byte> b2);
	int sodium_compare(const span<const std::byte> b1, const span<const std::byte> b2);

	void sodium_memzero(const span<std::byte> buffer);

	void sodium_bin2hex(const span<char> hex, const span<const std::byte> bin);

	void crypto_secretbox_easy(
			const span<std::byte> ciphertext,
			const span<const std::byte> message,
			const span<const std::byte> nonce,
			const span<const std::byte> key);

	void crypto_secretbox_open_easy(
			const span<std::byte> message,
			const span<const std::byte> ciphertext,
			const span<const std::byte> nonce,
			const span<const std::byte> key);

	void crypto_sign(
			const span<std::byte> signed_message,
			const span<const std::byte> message,
			const span<const std::byte> signing_key);

	void crypto_sign_open(
			const span<std::byte> verified_message,
			const span<const std::byte> signed_message,
			const span<const std::byte> signing_key);

	void sodium_mprotect_noaccess(void *pointer);
	void sodium_mprotect_readonly(void *pointer);
	void sodium_mprotect_readwrite(void *pointer);

	span<std::byte> sodium_pad(span<std::byte> buffer, const size_t unpadded_length, size_t blocksize);
	span<std::byte> sodium_unpad(span<std::byte> buffer, const size_t blocksize);
}

#endif /* LIB_SODIUM_WRAPPERS_H */
