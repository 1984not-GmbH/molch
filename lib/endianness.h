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

#include <cstdbool>
#include <algorithm>

#include "common.h"
#include "buffer.h"
#include "molch-exception.h"

#ifndef LIB_ENDIANNESS_H
#define LIB_ENDIANNESS_H

/*
 * Determine the current endianness at runtime.
 */
inline bool endianness_is_little_endian() {
	uint16_t number = 0x1;
	unsigned char* number_pointer = (unsigned char*) &number;
	return (number_pointer[0] == 0x1);
}

/*
 * Convert any integer type to a buffer in big endian format.
 */
template <typename IntegerType>
void to_big_endian(IntegerType integer, Buffer& output) {
	unsigned char& reference = reinterpret_cast<unsigned char&>(integer);

	if (!output.fits(sizeof(IntegerType))) {
		throw MolchException(INVALID_INPUT, "Invalid input to endianness to big endian.");
	}

	if (endianness_is_little_endian()) {
		std::reverse(&reference, &reference + sizeof(integer));
	}

	if (output.cloneFromRaw(&reference, sizeof(integer)) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy number.");
	}
}

/*
 * Get an integer from a buffer in big endian format.
 */
template <typename IntegerType>
void from_big_endian(IntegerType& integer, Buffer& buffer) {
	if ((buffer.content_length != sizeof(IntegerType))) {
		throw MolchException(INVALID_INPUT, "Invalid input to from_big_endian.");
	}

	unsigned char& reference = reinterpret_cast<unsigned char&>(integer);

	if (buffer.cloneToRaw(&reference, sizeof(IntegerType)) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy number.");
	}

	if (endianness_is_little_endian()) {
		std::reverse(&reference, &reference + sizeof(IntegerType));
	}
}

#endif
