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

/*
 * Get the name of a status type as a string.
 */
const char *return_status_get_name(status_type status) {
	switch (status) {
		case SUCCESS:
			return "SUCCESS";

		case GENERIC_ERROR:
			return "GENERIC_ERROR";

		case INVALID_INPUT:
			return "INVALID_INPUT";

		case INVALID_VALUE:
			return "INVALID_VALUE";

		case INCORRECT_BUFFER_SIZE:
			return "INCORRECT_BUFFER_SIZE";

		case BUFFER_ERROR:
			return "BUFFER_ERROR";

		case INCORRECT_DATA:
			return "INCORRECT_DATA";

		case INIT_ERROR:
			return "INIT_ERROR";

		case CREATION_ERROR:
			return "CREATION_ERROR";

		case ADDITION_ERROR:
			return "ADDITION_ERROR";

		case ALLOCATION_FAILED:
			return "ALLOCATION_FAILED";

		case NOT_FOUND:
			return "NOT_FOUND";

		case VERIFICATION_FAILED:
			return "VERIFICATION_FAILED";

		case EXPORT_ERROR:
			return "EXPORT_ERROR";

		case IMPORT_ERROR:
			return "IMPORT_ERROR";

		case KEYGENERATION_FAILED:
			return "KEYGENERATION_FAILED";

		case KEYDERIVATION_FAILED:
			return "KEYDERIVATION_FAILED";

		case SEND_ERROR:
			return "SEND_ERROR";

		case RECEIVE_ERROR:
			return "RECEIVE_ERROR";

		case DATA_FETCH_ERROR:
			return "DATA_FETCH_ERROR";

		case DATA_SET_ERROR:
			return "DATA_SET_ERROR";

		case ENCRYPT_ERROR:
			return "ENCRYPT_ERROR";

		case DECRYPT_ERROR:
			return "DECRYPT_ERROR";

		case CONVERSION_ERROR:
			return "CONVERSION_ERROR";

		case SIGN_ERROR:
			return "SIGN_ERROR";

		case VERIFY_ERROR:
			return "VERIFY_ERROR";

		case REMOVE_ERROR:
			return "REMOVE_ERROR";

		case SHOULDNT_HAPPEN:
			return "SHOULDNT_HAPPEN";

		case INVALID_STATE:
			return "INVALID_STATE";

		case OUTDATED:
			return "OUTDATED";

		default:
			return "(NULL)";
	}
}
