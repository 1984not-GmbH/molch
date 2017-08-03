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
#include <memory>

#ifndef LIB_SODIUM_WRAPPERS_H
#define LIB_SODIUM_WRAPPERS_H

template <class T>
class SodiumAllocator : public std::allocator<T> {
public:
	SodiumAllocator() = default;
	//TODO WTF is this and why do I need it? C++ is strange, especially the standard library!
	SodiumAllocator(const std::allocator<T>& other) {
		(void)other;
	}

	T* allocate(size_t size) {
		T* pointer = reinterpret_cast<T*> (sodium_malloc(size));
		if (pointer == nullptr) {
			throw std::bad_alloc();
		}

		return pointer;
	}

	T* allocate(size_t size, const void * hint) {
		(void)hint;
		return this->allocate(size);
	}

	void deallocate(T* pointer, size_t n) {
		(void)n;
		sodium_free(pointer);
	}
};

template <typename T>
class SodiumDeleter {
public:
	void operator()(T* object) {
		if (object != nullptr) {
			sodium_free(object);
		}
	}
};

/*
 * Calls sodium_malloc and throws std::bad_alloc if allocation fails
 */
void* throwing_sodium_malloc(size_t size);

#endif /* LIB_SODIUM_WRAPPERS_H */
