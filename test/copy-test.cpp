/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 1984not Security GmbH
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

#include <exception>
#include <iostream>
#include <array>

#include "../lib/copy.hpp"
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

int main() noexcept {
	try {
		std::array<std::byte,4> a;
		a[0] = static_cast<std::byte>(0xde);
		a[1] = static_cast<std::byte>(0xea);
		a[2] = static_cast<std::byte>(0xbe);
		a[3] = static_cast<std::byte>(0xef);

		std::array<std::byte,4> b;
		b[0] = static_cast<std::byte>(0x00);
		b[1] = static_cast<std::byte>(0x00);
		b[2] = static_cast<std::byte>(0x00);
		b[3] = static_cast<std::byte>(0x00);

		std::array<std::byte,3> c;
		c[0] = static_cast<std::byte>(0x00);
		c[1] = static_cast<std::byte>(0x00);
		c[2] = static_cast<std::byte>(0x00);


		TRY_VOID(copyFromTo(a, b));
		if (a != b) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to properly copy dead beef.");
		}

		auto copy_result{copyFromTo(a, c)};
		if (copy_result) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to detect size misalignment.");
		}

		TRY_VOID(copyFromTo(a, c, 2));
		if ((a[0] != c[0]) || (a[1] != c[1])) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to copy subset of both.");
		}

		TRY_VOID(copyFromTo(a, c, 3));

		auto copy_result2{copyFromTo(a, c, 4)};
		if (copy_result) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to copy over the end.");
		}

	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
