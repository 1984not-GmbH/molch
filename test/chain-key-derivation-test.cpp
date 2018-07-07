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
#include "utils.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//create random initial chain key
		ChainKey last_chain_key;
		last_chain_key.fillRandom();

		//print first chain key
		printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
		last_chain_key.printHex(std::cout) << std::endl;


		//derive a chain of chain keys
		ChainKey next_chain_key;
		unsigned int counter;
		for (counter = 1; counter <= 5; counter++) {
			TRY_WITH_RESULT(next_chain_key_result, last_chain_key.deriveChainKey());
			next_chain_key = next_chain_key_result.value();

			//print the derived chain key
			printf("Chain key Nr. %i:\n", counter);
			next_chain_key.printHex(std::cout) << std::endl;

			//check that chain keys are different
			if (last_chain_key == next_chain_key) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Derived chain key is identical."};
			}

			//move next_chain_key to last_chain_key
			last_chain_key = next_chain_key;
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
