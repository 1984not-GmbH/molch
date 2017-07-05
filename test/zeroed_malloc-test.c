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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../lib/zeroed_malloc.h"
#include "utils.h"

int main(void) {
	return_status status = return_status_init();

	char * const pointer = zeroed_malloc(100);
	if (pointer == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate with zeroed_malloc.");
	}

	printf("Checking size.\n");
	size_t size = 0;
	memcpy(&size, pointer - sizeof(size_t), sizeof(size_t));
	if (size != 100) {
		throw(INCORRECT_DATA, "Size stored in the memory location is incorrect.");
	}
	printf("size = %zu\n", size);

	printf("Checking pointer.\n");
	char *pointer_copy = NULL;
	memcpy(&pointer_copy, pointer - sizeof(size_t) - sizeof(void*), sizeof(void*));
	printf("pointer_copy = %p\n", (void*)pointer_copy);

	zeroed_free(pointer);

	void *new_pointer = protobuf_c_allocator(NULL, 20);
	protobuf_c_free(NULL, new_pointer);

cleanup:
	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
