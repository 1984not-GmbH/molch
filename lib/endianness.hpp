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

/*
 * Functions to convert different types of numbers to big endian (networ byte order) for
 * packet creation.
 */

#ifndef LIB_ENDIANNESS_H
#define LIB_ENDIANNESS_H

#include <algorithm>
#include <iterator>

#include "buffer.hpp"
#include "molch-exception.hpp"
#include "gsl.hpp"

namespace Molch {
	/*
	 * Determine the current endianness at runtime.
	 */
	static bool endianness_is_little_endian() {
		const uint16_t number{0x1};
		const auto* const number_pointer{reinterpret_cast<const unsigned char*>(&number)};
		return (number_pointer[0] == 0x1);
	}

	/*
	 * Convert any integer type to a buffer in big endian format.
	 */
	template <typename IntegerType>
	void to_big_endian(IntegerType integer, span<std::byte> output) {
		Expects(output.size() == sizeof(IntegerType));

		//uses unsigned char instead of std::byte because of the aliasing rules
		auto& reference{reinterpret_cast<unsigned char&>(integer)};

		if (endianness_is_little_endian()) {
			std::reverse(&reference, &reference + sizeof(integer));
		}

		std::copy(&reference, &reference + sizeof(integer), reinterpret_cast<unsigned char*>(output.data()));
	}

	/*
	 * Get an integer from a buffer in big endian format.
	 */
	template <typename IntegerType>
	void from_big_endian(IntegerType& integer, const span<const std::byte> input) {
		Expects(input.size() == sizeof(IntegerType));

		//uses unsigned char instead of std::byte because of the aliasing rules
		auto& reference{reinterpret_cast<unsigned char&>(integer)};

		std::copy(std::cbegin(input), std::cend(input), reinterpret_cast<std::byte*>(&reference));

		if (endianness_is_little_endian()) {
			std::reverse(&reference, &reference + sizeof(IntegerType));
		}
	}
}

#endif
