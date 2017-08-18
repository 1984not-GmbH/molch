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
#include <iostream>

#include "../lib/molch-exception.hpp"
#include "common.hpp"
#include "utils.hpp"

/*
 * Generates and prints a crypto_box keypair.
 */
void generate_and_print_keypair(
		Buffer& public_key, //crypto_box_PUBLICKEYBYTES
		Buffer& private_key, //crypto_box_SECRETKEYBYTES
		const std::string& name, //Name of the key owner (e.g. "Alice")
		const std::string& type) { //type of the key (e.g. "ephemeral")
	//check buffer sizes
	if (!public_key.fits(crypto_box_PUBLICKEYBYTES)
			|| !private_key.fits(crypto_box_SECRETKEYBYTES)) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "Public key buffer is too short.");
	}
	//generate keypair
	{
		int status_int = 0;
		status_int = crypto_box_keypair(public_key.content, private_key.content);
		if (status_int != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate keypair.");
		}
	}
	public_key.content_length = crypto_box_PUBLICKEYBYTES;
	private_key.content_length = crypto_box_SECRETKEYBYTES;

	//print keypair
	std::cout << name << "'s public " << type << " key (" << public_key.content_length << ":" << std::endl;
	public_key.printHex(std::cout);
	putchar('\n');
	std::cout << std::endl << name << "'s private " << type << " key (" << private_key.content_length << ":" << std::endl;
	private_key.printHex(std::cout) << std::endl;
}
