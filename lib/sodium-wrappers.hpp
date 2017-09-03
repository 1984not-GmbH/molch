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

	void crypto_box_keypair(const span<gsl::byte> public_key, const span<gsl::byte> private_key);
}

#endif /* LIB_SODIUM_WRAPPERS_H */
