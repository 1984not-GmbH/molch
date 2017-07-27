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

/*! \file
 * Zeroed malloc, a malloc that zeroes the space when freed.
 * This provides a malloc and a free function that store
 * the lenght of the allocated buffer and overwrite it with
 * zeroes when freed.
 */
#ifndef LIB_ZEROED_MALLOC_H
#define LIB_ZEROED_MALLOC_H

#include <memory>
#include <protobuf-c/protobuf-c.h>
#include "common.h"

/*!
 * Allocates a buffer of 'size' and stores it's size.
 *
 * \param size
 *   The amount of bytes to be allocated.
 * \return
 *   A pointer to a heap allocated memory region of size 'size'.
 */
void *zeroed_malloc(size_t size) __attribute__((warn_unused_result));

/*!
 * Allocates a buffer of 'size' and stores it's size.
 *
 * \param size
 *   The amount of bytes to be allocated.
 * \return
 *   A pointer to a heap allocated memory regtion of size 'size'.
 * \throws std::bad_alloc
 */
void *throwing_zeroed_malloc(size_t size) __attribute__((warn_unused_result));

/*!
 * Frees a buffer allocated with zeroed_malloc and securely
 * erases it with zeroes.
 *
 * \param pointer
 *   A pointer to the memory that was allocated via zeroed_malloc.
 */
void zeroed_free(void *pointer);

/*!
 * Wrapper around zeroed_malloc that can be used by Protobuf-C.
 *
 * \param allocator_data
 *   Opaque pointer that will get passed to the functions by Protobuf-C. Ignored!
 * \param size
 *   The amount of bytes to be allocated.
 * \return
 *   A pointer to a heap allocated memory region of size 'size'.
 */
void *protobuf_c_allocator(void *allocator_data, size_t size) __attribute__((warn_unused_result));

/*!
 * Wrapper around zeroed_free that can be used by Protobuf-C.
 *
 * \param allocator_data
 *   Opaque pointer that will get passed to the functions by Protobuf-C. Ignored!
 * \param pointer
 *   A pointer to the memory that was allocated via zeroed_malloc.
 */
void protobuf_c_free(void *allocator_data, void *pointer);

static ProtobufCAllocator protobuf_c_allocators __attribute__((unused)) = {
	&protobuf_c_allocator,
	&protobuf_c_free,
	NULL
};

template <class T>
class ZeroedAllocator : public std::allocator<T> {
public:
	T* allocate(size_t size) {
		T* pointer = reinterpret_cast<T*> (zeroed_malloc(size));
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
		zeroed_free(pointer);
	}
};

template <typename T>
class ZeroedDeleter {
public:
	void operator()(T* object) {
		if (object != nullptr) {
			zeroed_free(object);
		}
	}
};

#endif
