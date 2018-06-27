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

#ifdef __cplusplus
extern "C" {
#else
	#define class
#endif

// possible status types, either SUCCESS or a variety of error types.
typedef enum class status_type { //TODO add more error types
	SUCCESS = 0,
	GENERIC_ERROR,
	INVALID_VALUE,
	INCORRECT_BUFFER_SIZE,
	BUFFER_ERROR,
	INCORRECT_DATA,
	INIT_ERROR,
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
	UNSUPPORTED_PROTOCOL_VERSION,
	EXCEPTION,
	EXPECTATION_FAILED
} status_type;

typedef struct error_message error_message;
struct error_message {
	char * message;
	status_type status;
	error_message *next;
};

typedef struct return_status {
	status_type status;
	error_message *error;
} return_status;

#ifdef __cplusplus
}
#endif

#endif /* LIB_RETURN_STATUS_H */
