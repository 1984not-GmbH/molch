/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 Max Bruckner (FSMaxB) <max at maxbruckner dot de>
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

#ifndef LIB_COPY_HPP
#define LIB_COPY_HPP

#include <algorithm>
#include <limits>
#include <cstddef>

#include "gsl.hpp"
#include "result.hpp"


namespace Molch {
	inline result<void> copyFromTo(span<const std::byte> source, span<std::byte> destination, size_t length) {
		FulfillOrFail((source.size() >= length) && (destination.size() >= length) && (length < std::numeric_limits<ptrdiff_t>::max()));
		std::copy(std::begin(source), std::begin(source) + static_cast<ptrdiff_t>(length), std::begin(destination));

		return outcome::success();
	}

	inline result<void> copyFromTo(span<const std::byte> source, span<std::byte> destination) {
		FulfillOrFail(source.size() == destination.size());

		return copyFromTo(source, destination, source.size());
	}
}

 #endif /* LIB_COPY_HPP */