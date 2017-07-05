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

	//create buffers;
	buffer_t *chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	buffer_t *message_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);

	//create random chain key
	if (buffer_fill_random(chain_key, chain_key->buffer_length) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to create chain key.");
	}

	//print first chain key
	printf("Chain key (%zu Bytes):\n", chain_key->content_length);
	print_hex(chain_key);
	putchar('\n');

	//derive message key from chain key
	status = derive_message_key(message_key, chain_key);
	buffer_clear(chain_key);
	throw_on_error(KEYGENERATION_FAILED, "Failed to derive message key.");

	//print message key
	printf("Message key (%zu Bytes):\n", message_key->content_length);
	print_hex(message_key);
	putchar('\n');

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(chain_key);
	buffer_destroy_from_heap_and_null_if_valid(message_key);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
