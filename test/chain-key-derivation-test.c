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
#include <string.h>
#include <sodium.h>

#include "../lib/key-derivation.h"
#include "utils.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//buffer for derived chain keys
	buffer_t *next_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	//create random initial chain key
	buffer_t *last_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	if (buffer_fill_random(last_chain_key, last_chain_key->buffer_length) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to create last chain key.");
	}

	//print first chain key
	printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(last_chain_key);
	putchar('\n');


	//derive a chain of chain keys
	unsigned int counter;
	for (counter = 1; counter <= 5; counter++) {
		status = derive_chain_key(next_chain_key, last_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

		//print the derived chain key
		printf("Chain key Nr. %i:\n", counter);
		print_hex(next_chain_key);
		putchar('\n');

		//check that chain keys are different
		if (buffer_compare(last_chain_key, next_chain_key) == 0) {
			throw(INCORRECT_DATA, "Derived chain key is identical.");
		}

		//move next_chain_key to last_chain_key
		if (buffer_clone(last_chain_key, next_chain_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(last_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(next_chain_key);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
