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

#include <iostream>
#include <cstdlib>

#include "../lib/time.hpp"
#include "../lib/molch-exception.hpp"

using namespace Molch;

int main() noexcept {
	try {
		seconds ten_seconds{10};

		if (ten_seconds.count() != 10) {
			throw Exception{status_type::INCORRECT_DATA, "Ten seconds doesn't count as 10."};
		}
		std::cout << "Successfully tested seconds\n";

		auto one_hour{1h};
		seconds hour_seconds{one_hour};
		if (hour_seconds.count() != 3600) {
			throw Exception{status_type::INCORRECT_DATA, "One hour doesn't have 3600 seconds."};
		}
		std::cout << "Successfully tested hours\n";

		auto one_day{1_days};
		hours day_hours{one_day};
		if (day_hours.count() != 24) {
			throw Exception{status_type::INCORRECT_DATA, "One day doesn't have 24 hours."};
		}
		std::cout << "Successfully tested days\n";

		auto one_month{1_months};
		days month_hours{one_month};
		if (month_hours.count() != 31) {
			throw Exception{status_type::INCORRECT_DATA, "One month doesn't have 31 days."};
		}
		std::cout << "Successfully tested months\n";

	} catch (const Exception& exception) {
		exception.print(std::cerr) << std::endl;
	}

	return EXIT_SUCCESS;
}
