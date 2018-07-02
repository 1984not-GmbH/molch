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
#include "common.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		Molch::Key<50,Molch::KeyType::Key> master_key;
		master_key.fillRandom();
		printf("Master key:\n");
		master_key.printHex(std::cout) << std::endl;

		Molch::Key<60,Molch::KeyType::Key> subkey1;
		master_key.deriveTo(subkey1, 0);
		printf("First subkey:\n");
		subkey1.printHex(std::cout) << std::endl;

		Molch::Key<60,Molch::KeyType::Key> subkey2;
		master_key.deriveTo(subkey2, 1);
		printf("Second subkey:\n");
		subkey2.printHex(std::cout) << std::endl;

		if (subkey1 == subkey2) {
			throw Molch::Exception{status_type::KEYGENERATION_FAILED, "Both subkeys are the same."};
		}

		Molch::Key<60,Molch::KeyType::Key> subkey1_copy;
		master_key.deriveTo(subkey1_copy, 0);

		if (subkey1 != subkey1_copy) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to reproduce subkey."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
