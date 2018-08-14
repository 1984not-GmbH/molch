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

		Molch::EmptyableKey<50,Molch::KeyType::Key> master_key;
		master_key.fillRandom();
		printf("Master key:\n");
		std::cout << master_key << std::endl;

		TRY_WITH_RESULT(subkey1_result, (master_key.deriveSubkeyWithIndex<Molch::EmptyableKey<60,Molch::KeyType::Key>>(0)));
		const auto& subkey1{subkey1_result.value()};
		printf("First subkey:\n");
		std::cout << subkey1 << std::endl;

		TRY_WITH_RESULT(subkey2_result, (master_key.deriveSubkeyWithIndex<Molch::EmptyableKey<60,Molch::KeyType::Key>>(1)));
		const auto& subkey2{subkey2_result.value()};
		printf("Second subkey:\n");
		std::cout << subkey2 << std::endl;

		if (subkey1 == subkey2) {
			throw Molch::Exception{status_type::KEYGENERATION_FAILED, "Both subkeys are the same."};
		}

		TRY_WITH_RESULT(subkey1_copy_result, (master_key.deriveSubkeyWithIndex<Molch::EmptyableKey<60,Molch::KeyType::Key>>(0)));
		const auto& subkey1_copy{subkey1_copy_result.value()};
		if (subkey1 != subkey1_copy) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to reproduce subkey."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
