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

#ifndef LIB_MALLOC_HPP
#define LIB_MALLOC_HPP

#include <memory>

namespace Molch {
	template <typename T>
	T *throwing_malloc(size_t elements) {
		auto pointer = reinterpret_cast<T*>(calloc(elements, sizeof(T)));
		if (pointer == nullptr) {
			throw std::bad_alloc();
		}

		return pointer;
	}

	template <typename T>
	class MallocAllocator {
	public:
		using value_type = T;

		MallocAllocator() = default;
		template <typename U>
		constexpr MallocAllocator(const MallocAllocator<U>&) noexcept {}

		T* allocate(size_t elements) {
			return throwing_malloc<T>(elements);
		}

		void deallocate(T* pointer, size_t elements) noexcept {
			(void)elements;
			free(pointer);
		}
	};
	template <typename T, typename U>
	bool operator==(const MallocAllocator<T>&, const MallocAllocator<U>&) {
		return true;
	}
	template <typename T, typename U>
	bool operator!=(const MallocAllocator<T>&, const MallocAllocator<U>&) {
		return false;
	}

	template <typename T>
	class MallocDeleter {
	public:
		void operator()(T* object) {
			if (object != nullptr) {
				free(object);
			}
		}
	};
}

#endif /* LIB_MALLOC_HPP */
