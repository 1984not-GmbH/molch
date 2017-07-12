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

#include <cstdlib>
#include <sodium.h>
#include <cstring>

#include "zeroed_malloc.h"
#include "alignment.h"
#include "common.h"

/*! \file
 * The purpose of these functions is to implement a memory allocator that gets memory
 * from malloc and puts it's length and pointer to the start address to the beginning
 * of the allocated memory. (or to be precise: In front of the correctly aligned pointer
 * that is returned by the zeroed_malloc function.)
 */

void *zeroed_malloc(size_t size) {
	// start_pointer:size:padding:allocated_memory
	// the size is needed in order to overwrite it with zeroes later
	// the start_pointer has to be passed to free later

	size_t amount_to_allocate = size + sizeof(void*) + sizeof(size_t) + (alignof(max_align_t) - 1);

	char * const malloced_address = (char*)malloc(amount_to_allocate);
	if (malloced_address == NULL) {
		return NULL;
	}

	char *aligned_address = (char*)next_aligned_address(malloced_address + sizeof(size_t) + sizeof(void*), alignof(intmax_t));

	//write the size in front of the algined address
	memcpy(aligned_address - sizeof(size_t), &size, sizeof(size_t));
	//write the pointer from malloc in front of the size
	memcpy(aligned_address - sizeof(size_t) - sizeof(void*), &malloced_address, sizeof(void*));

	return aligned_address;
}

void zeroed_free(void *pointer) {
	if (pointer == NULL) {
		return;
	}

	size_t size;
	void *malloced_address;

	//get the size
	memcpy(&size, ((char*)pointer) - sizeof(size_t), sizeof(size_t));
	//get the original pointer
	memcpy(&malloced_address, ((char*)pointer) - sizeof(size_t) - sizeof(void*), sizeof(void*));

	sodium_memzero(pointer, size);

	free_and_null_if_valid(malloced_address);
}

void *protobuf_c_allocator(void *allocator_data __attribute__((unused)), size_t size) {
	return zeroed_malloc(size);
}

void protobuf_c_free(void *allocator_data __attribute__((unused)), void *pointer) {
	zeroed_free(pointer);
}
