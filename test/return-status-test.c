/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2016  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/return-status.h"
#include "utils.h"
#include "tracing.h"

return_status second_level() {
	return_status status = return_status_init();

	throw(GENERIC_ERROR, "Error on the second level!");

cleanup:
	return status;
}

return_status first_level() {
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
	if (status.error != NULL) {
		print_errors(&status);
	}
	if (printed_status != NULL) {
		free(printed_status);
	}
	return_status_destroy_errors(&status);

	if (error_stack != NULL) {
		free(error_stack);
	}

	return status.status;
}
