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

#include "../lib/header.hpp"
#include "../lib/constants.h"
#include "utils.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//create ephemeral key
		PublicKey our_public_ephemeral_key;
		randombytes_buf(our_public_ephemeral_key);
		std::cout << "Our public ephemeral key (" << our_public_ephemeral_key.size() << " Bytes):\n";
		std::cout << our_public_ephemeral_key;

		//message numbers
		uint32_t message_number{2};
		uint32_t previous_message_number{10};
		std::cout << "Message number: " << message_number << '\n';
		std::cout << "Previous message number: " << previous_message_number << '\n';
		putchar('\n');

		//create the header
		TRY_WITH_RESULT(header, header_construct(
				our_public_ephemeral_key,
				message_number,
				previous_message_number));

		//print the header
		std::cout << "Header (" << header.value().size() << " Bytes):\n";
		std::cout << header.value();
		putchar('\n');

		//get data back out of the header again
		TRY_WITH_RESULT(extracted_header, header_extract(header.value()));

		std::cout << "Extracted public ephemeral key (" << extracted_header.value().their_public_ephemeral.size() << " Bytes):\n";
		std::cout << extracted_header.value().their_public_ephemeral;
		std::cout << "Extracted message number: " << extracted_header.value().message_number << '\n';
		std::cout << "Extracted previous message number: " << extracted_header.value().previous_message_number << '\n';
		putchar('\n');

		//compare them
		if (our_public_ephemeral_key != extracted_header.value().their_public_ephemeral) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Public ephemeral keys don't match."};
		}
		std::cout << "Public ephemeral keys match.\n";

		if (message_number != extracted_header.value().message_number) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Message number doesn't match."};
		}
		std::cout << "Message numbers match.\n";

		if (previous_message_number != extracted_header.value().previous_message_number) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Previous message number doesn't match."};
		}
		std::cout << "Previous message numbers match.\n";
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
