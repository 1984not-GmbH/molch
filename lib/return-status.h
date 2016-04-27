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

#ifndef LIB_RETURN_STATUS_H
#define LIB_RETURN_STATUS_H

// possible status types, either SUCCESS or a variety of error types.
typedef enum status_type { //TODO add more error types
	SUCCESS = 0,
	GENERIC_ERROR,
	INVALID_INPUT,
	INVALID_VALUE,
	INCORRECT_BUFFER_SIZE,
	BUFFER_ERROR,
	INCORRECT_DATA,
	INIT_ERROR,
	CREATION_ERROR,
	ADDITION_ERROR,
	ALLOCATION_FAILED,
	NOT_FOUND,
	VERIFICATION_FAILED,
	EXPORT_ERROR,
	IMPORT_ERROR,
	KEYGENERATION_FAILED,
	SEND_ERROR,
	RECEIVE_ERROR,
	DATA_FETCH_ERROR,
	DATA_SET_ERROR,
	ENCRYPT_ERROR,
	DECRYPT_ERROR,
	CONVERSION_ERROR,
	SIGN_ERROR,
	REMOVE_ERROR
} status_type;

typedef struct error_message error_message;
struct error_message {
	const char * message;
	status_type status;
	error_message *next;
};

typedef struct return_status {
	status_type status;
	error_message *error;
} return_status;

return_status return_status_init();

status_type return_status_add_error_message(
		return_status *const status_object,
		const char *const message,
		const status_type status) __attribute__((warn_unused_result));

void return_status_destroy_errors(return_status * const status);


//This assumes that there is a return_status struct and there is a "cleanup" label to jump to.
#define throw(status_type_value, message) {\
	status.status = status_type_value;\
	if (message != NULL) {\
		status_type type = return_status_add_error_message(&status, message, status_type_value);\
		if (type != SUCCESS) {\
			status.status = type;\
		}\
	} else {\
		status.error = NULL;\
	}\
\
	goto cleanup;\
}

//Execute code on error
#define on_error(code) \
if (status.status != SUCCESS) {\
	code\
}

#define throw_on_error(status_type_value, message) on_error(throw(status_type_value, message))

#endif
