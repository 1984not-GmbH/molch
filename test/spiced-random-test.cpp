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
#include "utils.hpp"
#include "exception.hpp"

using namespace Molch;

int main() noexcept {
	try {
		TRY_VOID(Molch::sodium_init());

		//some random user input (idiot bashing his head on the keyboard)
		Buffer spice{"aaeipoewur+ue 093+2ss3+2ue+ ss09234rt #2ss 0iw4eraep9ui23+ 03943"};
		std::cout << "\"Random\" input from the user (" << spice.size() << " Bytes):\n";
		std::cout << "String: " << std::string_view(byte_to_char(spice.data()), spice.size()) << "\n";
		std::cout << "Hex:\n";
		std::cout << spice << std::endl;

		//fill buffer with spiced random data
		TRY_WITH_RESULT(output1_result, spiced_random(spice, 42));
		const auto& output1{output1_result.value()};

		std::cout << "Spiced random data 1 (" << output1.size() << " Bytes):\n";
		std::cout << output1 << std::endl;


		//fill buffer with spiced random data
		TRY_WITH_RESULT(output2_result, spiced_random(spice, 42));
		const auto& output2{output2_result.value()};

		std::cout << "Spiced random data 2 (" << output2.size() << " Bytes):\n";
		std::cout << output2;
		putchar('\n');

		//compare the two (mustn't be identical!)
		if (output1 == output2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Random numbers aren't random."};
		}

		//don't crash with output length 0
		if (spiced_random(spice, 0).has_value()) {
			throw Exception(status_type::GENERIC_ERROR, "");
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
