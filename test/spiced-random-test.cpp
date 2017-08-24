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

#include "../lib/spiced-random.hpp"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

using namespace Molch;

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//some random user input (idiot bashing his head on the keyboard)
		Buffer spice{"aäipoewur+ü 093+2ß3+2ü+ ß09234rt #2ß 0iw4eräp9ui23+ 03943"};
		printf("\"Random\" input from the user (%zu Bytes):\n", spice.size);
		printf("String: %.*s\n", static_cast<int>(spice.size), spice.content);
		printf("Hex:\n");
		spice.printHex(std::cout) << std::endl;

		//fill buffer with spiced random data
		Buffer output1{42, 0};
		spiced_random(output1, spice, output1.capacity());

		printf("Spiced random data 1 (%zu Bytes):\n", output1.size);
		output1.printHex(std::cout) << std::endl;


		//fill buffer with spiced random data
		Buffer output2{42, 0};
		spiced_random(output2, spice, output2.capacity());

		printf("Spiced random data 2 (%zu Bytes):\n", output2.size);
		output2.printHex(std::cout);
		putchar('\n');

		//compare the two (mustn't be identical!)
		if (output1 == output2) {
			throw Molch::Exception(INCORRECT_DATA, "Random numbers aren't random.");
		}

		//don't crash with output length 0
		try {
			spiced_random(output1, spice, 0);
		} catch (const Molch::Exception& exception) {
			//on newer libsodium versions, output lengths of zero aren't supported
		}
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
