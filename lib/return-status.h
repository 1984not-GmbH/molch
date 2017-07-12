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

#ifndef LIB_RETURN_STATUS_H
#define LIB_RETURN_STATUS_H

#include "common.h"

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
	KEYDERIVATION_FAILED,
	SEND_ERROR,
	RECEIVE_ERROR,
	DATA_FETCH_ERROR,
	DATA_SET_ERROR,
	ENCRYPT_ERROR,
	DECRYPT_ERROR,
	CONVERSION_ERROR,
	SIGN_ERROR,
	VERIFY_ERROR,
	REMOVE_ERROR,
	SHOULDNT_HAPPEN,
	INVALID_STATE,
	OUTDATED,
	PROTOBUF_PACK_ERROR,
	PROTOBUF_UNPACK_ERROR,
	PROTOBUF_MISSING_ERROR,
	UNSUPPORTED_PROTOCOL_VERSION
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

return_status return_status_init(void);

status_type return_status_add_error_message(
		return_status *const status_object,
		const char *const message,
		const status_type status) __attribute__((warn_unused_result));

void return_status_destroy_errors(return_status * const status);

/*
 * Get the name of a status type as a string.
 */
const char *return_status_get_name(status_type status);

/*
 * Pretty print the error stack into a buffer.
 *
 * Don't forget to free with "free" after usage.
 */
char *return_status_print(const return_status * const status, size_t *length) __attribute__((warn_unused_result));


//This assumes that there is a return_status struct and there is a "cleanup" label to jump to.
#define THROW(status_type_value, message) {\
	status.status = status_type_value;\
	if (message != NULL) {\
		status_type THROW_type = return_status_add_error_message(&status, message, status_type_value);\
		if (THROW_type != SUCCESS) {\
			status.status = THROW_type;\
		}\
	} else {\
		status.error = NULL;\
	}\
\
	goto cleanup;\
}

//Execute code on error
#define on_error if (status.status != SUCCESS)

#define THROW_on_error(status_type_value, message) on_error{THROW(status_type_value, message)}

#define THROW_on_failed_alloc(pointer) \
	if (pointer == NULL) {\
		THROW(ALLOCATION_FAILED, "Failed to allocate memory.");\
	}

#endif
