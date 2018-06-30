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

using namespace Molch;

/*
 * Generates and prints a crypto_box keypair.
 */
MOLCH_PUBLIC(void) generate_and_print_keypair(
		PublicKey& public_key,
		PrivateKey& private_key,
		const std::string& name, //Name of the key owner (e.g. "Alice")
		const std::string& type) { //type of the key (e.g. "ephemeral")
	//generate keypair
	crypto_box_keypair(public_key, private_key);
	public_key.empty = false;
	private_key.empty = false;

	//print keypair
	std::cout << name << "'s public " << type << " key (" << public_key.size() << ":" << std::endl;
	public_key.printHex(std::cout);
	putchar('\n');
	std::cout << std::endl << name << "'s private " << type << " key (" << private_key.size() << ":" << std::endl;
	private_key.printHex(std::cout) << std::endl;
}
