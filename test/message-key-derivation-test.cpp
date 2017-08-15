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

#include "../lib/key-derivation.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			return -1;
		}

		//create buffers;
		Buffer chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		Buffer message_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		exception_on_invalid_buffer(chain_key);
		exception_on_invalid_buffer(message_key);

		//create random chain key
		if (chain_key.fillRandom(chain_key.getBufferLength()) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to create chain key.");
		}

		//print first chain key
		printf("Chain key (%zu Bytes):\n", chain_key.content_length);
		std::cout << chain_key.toHex();
		putchar('\n');

		//derive message key from chain key
		derive_message_key(message_key, chain_key);
		chain_key.clear();

		//print message key
		printf("Message key (%zu Bytes):\n", message_key.content_length);
		std::cout << message_key.toHex();
		putchar('\n');
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
