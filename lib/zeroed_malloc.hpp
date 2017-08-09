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

#include "molch-exception.hpp"

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
template <typename T>
T *throwing_zeroed_malloc(size_t size) {
	// start_pointer:size:padding:allocated_memory
	// the size is needed in order to overwrite it with zeroes later
	// the start_pointer has to be passed to free later

	size_t amount_to_allocate = size + sizeof(void*) + sizeof(size_t) + (alignof(T) - 1);

	auto allocated_address = std::unique_ptr<unsigned char[]>(new unsigned char[amount_to_allocate]);
	unsigned char *address = allocated_address.get();

	size_t space = amount_to_allocate - sizeof(size_t) - sizeof(void*);
	unsigned char *aligned_address = address + sizeof(size_t) + sizeof(void*);
	if (std::align(alignof(T), size, reinterpret_cast<void*&>(aligned_address), space) == nullptr) {
		throw MolchException(ALLOCATION_FAILED, "Failed to align memory.");
	}

	//NOTE: This has to be copied as bytes because of possible alignment issues
	//write the size in front of the aligned address
	std::copy(reinterpret_cast<unsigned char*>(&size), reinterpret_cast<unsigned char*>(&size + 1), aligned_address - sizeof(size_t));
	//write the pointer from malloc in front of the size
	std::copy(reinterpret_cast<unsigned char*>(&address), reinterpret_cast<unsigned char*>(&address + 1), aligned_address - sizeof(size_t) - sizeof(void*));

	allocated_address.release();

	return reinterpret_cast<T*>(aligned_address);
}

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
	nullptr
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
