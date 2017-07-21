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
#include <exception>
#include <iostream>

#include "../lib/key-derivation.h"
#include "../lib/molch-exception.h"
#include "utils.h"

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create random initial chain key
		Buffer last_chain_key(crypto_auth_BYTES, crypto_auth_BYTES);
		exception_on_invalid_buffer(last_chain_key);
		if (last_chain_key.fillRandom(last_chain_key.getBufferLength()) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to create last chain key.");
		}

		//print first chain key
		printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
		print_hex(last_chain_key);
		putchar('\n');


		//derive a chain of chain keys
		Buffer next_chain_key(crypto_auth_BYTES, crypto_auth_BYTES);
		exception_on_invalid_buffer(next_chain_key);
		unsigned int counter;
		for (counter = 1; counter <= 5; counter++) {
			derive_chain_key(next_chain_key, last_chain_key);

			//print the derived chain key
			printf("Chain key Nr. %i:\n", counter);
			print_hex(next_chain_key);
			putchar('\n');

			//check that chain keys are different
			if (last_chain_key == next_chain_key) {
				throw MolchException(INCORRECT_DATA, "Derived chain key is identical.");
			}

			//move next_chain_key to last_chain_key
			if (last_chain_key.cloneFrom(&next_chain_key) != 0) {
				throw MolchException(BUFFER_ERROR, "Failed to copy chain key.");
			}
		}
	} catch (const MolchException& exception) {
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
