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
#include <cstring>
#include <iostream>

#include "../include/molch/return-status.h"
#include "../lib/destroyers.hpp"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

using namespace Molch;

static return_status second_level() noexcept {
	auto status{return_status_init()};

	THROW(status_type::GENERIC_ERROR, "Error on the second level!");

cleanup:
	return status;
}

static return_status first_level() noexcept {
	auto status{return_status_init()};

	status = second_level();
	THROW_on_error(status_type::GENERIC_ERROR, "Error on the first level!");

cleanup:
	return status;
}

int main() noexcept {
	auto status{return_status_init()};

	char *error_stack{nullptr};
	char *printed_status{nullptr};

	//check if it was correctly initialized
	if ((status.status != status_type::SUCCESS) || (status.error != nullptr)) {
		fprintf(stderr, "ERROR: Failed to initialize return statu!\n");
		return EXIT_FAILURE;
	}
	printf("Initialized return status!\n");

	// check the error stack
	status = first_level();
	if (strcmp(status.error->message, "Error on the first level!") != 0) {
		fprintf(stderr, "ERROR: First error message is incorrect!\n");
		status.status = status_type::GENERIC_ERROR;
		goto cleanup;
	}
	if (strcmp(status.error->next->message, "Error on the second level!") != 0) {
		fprintf(stderr, "ERROR: Second error message is incorrect!\n");
		status.status = status_type::GENERIC_ERROR;
		goto cleanup;
	}
	printf("Successfully created error stack.\n");

	{
		auto printed{return_status_print(status)};
		auto stack_print_length{printed.size()};
		error_stack = printed.data();
		if (error_stack == nullptr) {
			fprintf(stderr, "ERROR: Failed to print error stack.\n");
			status.status = status_type::GENERIC_ERROR;
			goto cleanup;
		}
		printf("%s\n", error_stack);

		Buffer stack_trace{"ERROR\nerror stack trace:\n0: GENERIC_ERROR, Error on the first level!\n1: GENERIC_ERROR, Error on the second level!\n"};
		if (stack_trace.compareToRaw({reinterpret_cast<std::byte*>(error_stack), stack_print_length}) != 0) {
			THROW(status_type::INCORRECT_DATA, "Stack trace looks differently than expected.");
		}
	}

	status.status = status_type::SUCCESS;
	return_status_destroy_errors(status);

	//more tests for return_status_print()
	{
		auto successful_status{return_status_init()};
		Buffer success_buffer{"SUCCESS"};
		auto printed{return_status_print(successful_status)};
		auto printed_status_length{printed.size()};
		printed_status = printed.data();
		if (success_buffer.compareToRaw({reinterpret_cast<std::byte*>(printed_status), printed_status_length}) != 0) {
			THROW(status_type::INCORRECT_DATA, "molch_print_status produces incorrect output.");
		}
	}

	//test converting return_status to Molch::Exception
	{
		std::cout << "Test Molch::Exception:\n";
		auto local_status{first_level()};
		Molch::Exception{local_status}.print(std::cout) << std::endl;
	}

cleanup:
	on_error {
		print_errors(status);
	}
	free_and_null_if_valid(printed_status);
	return_status_destroy_errors(status);

	free_and_null_if_valid(error_stack);

	return static_cast<int>(status.status);
}
