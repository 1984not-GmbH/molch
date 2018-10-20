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
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES O	F
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "../include/molch/return-status.h"
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "inline-utils.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	auto status{success_status};

	char *printed_status{nullptr};

	//check if it was correctly initialized
	if ((status.status != status_type::SUCCESS) || (status.error != nullptr)) {
		std::cerr << "ERROR: Failed to initialize return status!\n";
		return EXIT_FAILURE;
	}
	std::cout << "Initialized return status!\n";

	//more tests for return_status_print()
	{
		auto successful_status{success_status};
		Buffer success_buffer{"SUCCESS"};
		auto printed{return_status_print(successful_status)};
		auto printed_status_length{printed.size()};
		printed_status = printed.data();
		TRY_WITH_RESULT(comparison, success_buffer.compareToRaw({char_to_byte(printed_status), printed_status_length}));
		if (!comparison.value()) {
			status.status = status_type::INCORRECT_DATA;
			status.error = "molch_print_status produces incorrect output.";
			goto cleanup; //NOLINT
		}
	}

cleanup:
	on_error {
		std::cout << Exception(status);
	}
	free_and_null_if_valid(printed_status);

	return static_cast<int>(status.status);
}
