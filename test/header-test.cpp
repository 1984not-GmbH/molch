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
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

int main(void) {
	try {
		//create buffers
		Buffer our_public_ephemeral_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer extracted_public_ephemeral_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		exception_on_invalid_buffer(our_public_ephemeral_key);
		exception_on_invalid_buffer(extracted_public_ephemeral_key);

		uint32_t message_number;
		uint32_t previous_message_number;


		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		int status_int;
		//create ephemeral key
		status_int = our_public_ephemeral_key.fillRandom(our_public_ephemeral_key.content_length);
		if (status_int != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to create our public ephemeral.");
		}
		printf("Our public ephemeral key (%zu Bytes):\n", our_public_ephemeral_key.content_length);
		std::cout << our_public_ephemeral_key.toHex();

		//message numbers
		message_number = 2;
		previous_message_number = 10;
		printf("Message number: %u\n", message_number);
		printf("Previous message number: %u\n", previous_message_number);
		putchar('\n');

		//create the header
		std::unique_ptr<Buffer> header = header_construct(
				our_public_ephemeral_key,
				message_number,
				previous_message_number);

		//print the header
		printf("Header (%zu Bytes):\n", header->content_length);
		std::cout << header->toHex();
		putchar('\n');

		//get data back out of the header again
		uint32_t extracted_message_number;
		uint32_t extracted_previous_message_number;
		header_extract(
				extracted_public_ephemeral_key,
				extracted_message_number,
				extracted_previous_message_number,
				*header);

		printf("Extracted public ephemeral key (%zu Bytes):\n", extracted_public_ephemeral_key.content_length);
		std::cout << extracted_public_ephemeral_key.toHex();
		printf("Extracted message number: %u\n", extracted_message_number);
		printf("Extracted previous message number: %u\n", extracted_previous_message_number);
		putchar('\n');

		//compare them
		if (our_public_ephemeral_key.compare(&extracted_public_ephemeral_key) != 0) {
			throw MolchException(INVALID_VALUE, "Public ephemeral keys don't match.");
		}
		printf("Public ephemeral keys match.\n");

		if (message_number != extracted_message_number) {
			throw MolchException(INVALID_VALUE, "Message number doesn't match.");
		}
		printf("Message numbers match.\n");

		if (previous_message_number != extracted_previous_message_number) {
			throw MolchException(INVALID_VALUE, "Previous message number doesn't match.");
		}
		printf("Previous message numbers match.\n");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
