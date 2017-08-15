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
#include <sstream>
#include <string.h>

#include "../lib/molch-exception.hpp"
#include "utils.hpp"

static void second_level(void) {
	throw MolchException(GENERIC_ERROR, "Error on the second level!");
}

static void first_level(void) {
	try {
		second_level();
	} catch(MolchException& exception) {
		throw exception.add(MolchError(GENERIC_ERROR, "Error on the first level!"));
	}
}

int main(void) noexcept {
	// check the error stack
	try {
		first_level();
	} catch(const std::exception& exception) {
		if (strcmp(exception.what(), "MolchException") != 0) {
			std::cerr << "Exception is not a MolchException. Terminating" << std::endl;
			return EXIT_FAILURE;
		}
		return_status status = static_cast<const MolchException&>(exception).toReturnStatus();
		if (strcmp(status.error->message, "Error on the first level!") != 0) {
			fprintf(stderr, "ERROR: First error message is incorrect!\n");
			return EXIT_FAILURE;
		}
		if (strcmp(status.error->next->message, "Error on the second level!") != 0) {
			std::cerr << "ERROR: Second error message is incorrect!" << std::endl;
			return EXIT_FAILURE;
		}
		return_status_destroy_errors(&status);

		std::stringstream stream;
		static_cast<const MolchException&>(exception).print(stream);
		auto error_message = stream.str();
		if (error_message != "ERROR\nerror stack trace:\n0: GENERIC_ERROR, Error on the first level!\n1: GENERIC_ERROR, Error on the second level!\n") {
			std::cerr << error_message << std::endl;
			std::cerr << "Failed to correctly print error stack." << std::endl;
			return EXIT_FAILURE;
		}
	}
	printf("Successfully created error stack.\n");

	return EXIT_SUCCESS;
}
