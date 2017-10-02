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

#ifndef LIB_TIME_HPP
#define LIB_TIME_HPP

#include <chrono>
#include <ctime>

namespace Molch {
	using namespace std::literals::chrono_literals;
	using seconds = std::chrono::seconds;
	using hours = std::chrono::hours;
	using days = std::chrono::duration<int64_t,std::ratio<3600*24>>;
	using months = std::chrono::duration<int64_t,std::ratio<3600*24*31>>;

	seconds now();

	//literals
	constexpr days operator""_days(const unsigned long long amount) {
		return days{amount};
	}
	constexpr months operator""_months(const unsigned long long amount) {
		return months{amount};
	}
}

#endif /* LIB_TIME_HPP */
