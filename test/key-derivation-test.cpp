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
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "common.hpp"

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create buffers
		Buffer master_key(50, 50);
		Buffer subkey1(60, 60);
		Buffer subkey2(60, 60);
		Buffer subkey1_copy(60, 60);

		exception_on_invalid_buffer(master_key);
		exception_on_invalid_buffer(subkey1);
		exception_on_invalid_buffer(subkey2);
		exception_on_invalid_buffer(subkey1_copy);

		int status_int = master_key.fillRandom(master_key.getBufferLength());
		if (status_int != 0) {
			throw MolchException(KEYDERIVATION_FAILED, "Failed to generate master key.");
		}
		printf("Master key:\n");
		std::cout << master_key.toHex();
		putchar('\n');

		derive_key(subkey1, subkey1.getBufferLength(), master_key, 0);
		printf("First subkey:\n");
		std::cout << subkey1.toHex();
		putchar('\n');

		derive_key(subkey2, subkey2.getBufferLength(), master_key, 1);
		printf("Second subkey:\n");
		std::cout << subkey2.toHex();
		putchar('\n');

		if (subkey1 == subkey2) {
			throw MolchException(KEYGENERATION_FAILED, "Both subkeys are the same.");
		}

		derive_key(subkey1_copy, subkey1_copy.getBufferLength(), master_key, 0);

		if (subkey1 != subkey1_copy) {
			throw MolchException(INCORRECT_DATA, "Failed to reproduce subkey.");
		}
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
