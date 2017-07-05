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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/return-status.h"
#include "utils.h"

static return_status second_level(void) {
	return_status status = return_status_init();

	throw(GENERIC_ERROR, "Error on the second level!");

cleanup:
	return status;
}

static return_status first_level(void) {
	return_status status = return_status_init();

	status = second_level();
	throw_on_error(GENERIC_ERROR, "Error on the first level!");

cleanup:
	return status;
}

int main(void) {
	return_status status = return_status_init();

	char *error_stack = NULL;
	unsigned char *printed_status = NULL;

	//check if it was correctly initialized
	if ((status.status != SUCCESS) || (status.error != NULL)) {
		fprintf(stderr, "ERROR: Failed to initialize return statu!\n");
		return EXIT_FAILURE;
	}
	printf("Initialized return status!\n");

	// check the error stack
	status = first_level();
	if (strcmp(status.error->message, "Error on the first level!") != 0) {
		fprintf(stderr, "ERROR: First error message is incorrect!\n");
		status.status = GENERIC_ERROR;
		goto cleanup;
	}
	if (strcmp(status.error->next->message, "Error on the second level!") != 0) {
		fprintf(stderr, "ERROR: Second error message is incorrect!\n");
		status.status = GENERIC_ERROR;
		goto cleanup;
	}
	printf("Successfully created error stack.\n");

	size_t stack_print_length = 0;
	error_stack = return_status_print(&status, &stack_print_length);
	if (error_stack == NULL) {
		fprintf(stderr, "ERROR: Failed to print error stack.\n");
		status.status = GENERIC_ERROR;
		goto cleanup;
	}
	printf("%s\n", error_stack);

	buffer_create_from_string(stack_trace, "ERROR\nerror stack trace:\n000: GENERIC_ERROR, Error on the first level!\n001: GENERIC_ERROR, Error on the second level!\n");
	if (buffer_compare_to_raw(stack_trace, (unsigned char*)error_stack, stack_print_length) != 0) {
		throw(INCORRECT_DATA, "Stack trace looks differently than expected.");
	}

	status.status = SUCCESS;
	return_status_destroy_errors(&status);

	//more tests for return_status_print()
	return_status successful_status = return_status_init();
	buffer_create_from_string(success_buffer, "SUCCESS");
	size_t printed_status_length = 0;
	printed_status = (unsigned char*) return_status_print(&successful_status, &printed_status_length);
	if (buffer_compare_to_raw(success_buffer, printed_status, printed_status_length) != 0) {
		throw(INCORRECT_DATA, "molch_print_status produces incorrect output.");
	}

cleanup:
	on_error {
		print_errors(&status);
	}
	free_and_null_if_valid(printed_status);
	return_status_destroy_errors(&status);

	free_and_null_if_valid(error_stack);

	return status.status;
}
