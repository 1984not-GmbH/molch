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

#include <algorithm>
#include <cstdlib>
#include <sodium.h>
#include <cstddef>

#include "zeroed_malloc.hpp"

/*! \file
 * The purpose of these functions is to implement a memory allocator that gets memory
 * from malloc and puts it's length and pointer to the start address to the beginning
 * of the allocated memory. (or to be precise: In front of the correctly aligned pointer
 * that is returned by the zeroed_malloc function.)
 */

namespace Molch {
	void *zeroed_malloc(size_t size) {
		try {
			return reinterpret_cast<void*>(throwing_zeroed_malloc<max_align_t>(size));
		} catch (const std::exception& exception) {
			return nullptr;
		}
	}

	void zeroed_free(void *pointer) {
		if (pointer == nullptr) {
			return;
		}

		size_t size;
		unsigned char *malloced_address;

		//NOTE: This has to be copied as bytes because of possible alignment issues
		//get the size
		std::copy(reinterpret_cast<unsigned char*>(pointer) - sizeof(size_t), reinterpret_cast<unsigned char*>(pointer), reinterpret_cast<unsigned char*>(&size));
		//get the original pointer
		std::copy(reinterpret_cast<unsigned char*>(pointer) - sizeof(size_t) - sizeof(void*), reinterpret_cast<unsigned char*>(pointer) - sizeof(size_t), reinterpret_cast<unsigned char*>(&malloced_address));

		sodium_memzero(pointer, size);

		delete[] malloced_address;
	}

	void *protobuf_c_allocator(void *allocator_data __attribute__((unused)), size_t size) {
		return zeroed_malloc(size);
	}

	void protobuf_c_free(void *allocator_data __attribute__((unused)), void *pointer) {
		zeroed_free(pointer);
	}
}
