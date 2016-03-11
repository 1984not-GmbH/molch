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

#include <malloc.h>
#include "return-status.h"

inline return_status return_status_init() {
	return_status status = {
		SUCCESS,
		NULL
	};
	return status;
}

status_type return_status_add_error_message(
		return_status *const status_object,
		const char *const message,
		const status_type status) {
	if (status_object == NULL) {
		return INVALID_INPUT;
	}

	if (message == NULL) {
		return SUCCESS;
	}

	error_message *error = malloc(sizeof(error_message));
	if (error == NULL) {
		return ALLOCATION_FAILED;
	}

	error->next = status_object->error;
	error->message = message;
	error->status = status;

	status_object->error = error;

	return SUCCESS;
}

void return_status_destroy_errors(return_status * const status) {
	if (status == NULL) {
		return;
	}

	while (status->error != NULL) {
		error_message *next_error = status->error->next;
		free(status->error);
		status->error = next_error;
	}
}
