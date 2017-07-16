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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>

#include "../lib/key-derivation.h"
#include "utils.h"
#include "common.h"

int main(void) noexcept {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//create buffers
	Buffer *master_key = Buffer::create(50, 50);
	Buffer *subkey1 = Buffer::create(60, 60);
	Buffer *subkey2 = Buffer::create(60, 60);
	Buffer *subkey1_copy = Buffer::create(60, 60);

	int status_int = 0;
	status_int = master_key->fillRandom(master_key->getBufferLength());
	if (status_int != 0) {
		THROW(KEYDERIVATION_FAILED, "Failed to generate master key.");
	}
	printf("Master key:\n");
	print_hex(master_key);
	putchar('\n');

	status = derive_key(*subkey1, subkey1->getBufferLength(), *master_key, 0);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive first subkey.");
	printf("First subkey:\n");
	print_hex(subkey1);
	putchar('\n');

	status = derive_key(*subkey2, subkey2->getBufferLength(), *master_key, 1);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive the second subkey.");
	printf("Second subkey:\n");
	print_hex(subkey2);
	putchar('\n');

	if (subkey1->compare(subkey2) == 0) {
		THROW(KEYGENERATION_FAILED, "Both subkeys are the same.");
	}

	status = derive_key(*subkey1_copy, subkey1_copy->getBufferLength(), *master_key, 0);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive copy of the first subkey.");

	if (subkey1->compare(subkey1_copy) != 0) {
		THROW(INCORRECT_DATA, "Failed to reproduce subkey.");
	}

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(master_key);
	buffer_destroy_from_heap_and_null_if_valid(subkey1);
	buffer_destroy_from_heap_and_null_if_valid(subkey2);
	buffer_destroy_from_heap_and_null_if_valid(subkey1_copy);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
