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

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "return-status.h"
#include "buffer.h"

extern return_status return_status_init() {
	return_status status = {
		SUCCESS,
		nullptr
	};
	return status;
}

status_type return_status_add_error_message(
		return_status *const status_object,
		const char *const message,
		const status_type status) {
	if (status_object == nullptr) {
		return INVALID_INPUT;
	}

	if (message == nullptr) {
		return SUCCESS;
	}

	error_message *error = (error_message*)malloc(sizeof(error_message));
	if (error == nullptr) {
		return ALLOCATION_FAILED;
	}

	error->next = status_object->error;
	error->message = message;
	error->status = status;

	status_object->error = error;

	return SUCCESS;
}

void return_status_destroy_errors(return_status * const status) {
	if (status == nullptr) {
		return;
	}

	while (status->error != nullptr) {
		error_message *next_error = status->error->next;
		free_and_null_if_valid(status->error);
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

		case PROTOBUF_PACK_ERROR:
			return "PROTOBUF_PACK_ERROR";

		case PROTOBUF_UNPACK_ERROR:
			return "PROTOBUF_UNPACK_ERROR";

		case PROTOBUF_MISSING_ERROR:
			return "PROTOBUF_MISSING_ERROR";

		case UNSUPPORTED_PROTOCOL_VERSION:
			return "UNSUPPORTED_PROTOCOL_VERSION";

		default:
			return "(nullptr)";
	}
}

/*
 * Pretty print the error stack into a buffer.
 *
 * Don't forget to free with "free" after usage.
 */
char *return_status_print(const return_status * const status_to_print, size_t *length) {
	return_status status = return_status_init();

	Buffer *output = nullptr;

	size_t output_size = 1; // 1 because of '\0';

	//check input
	if (status_to_print == nullptr) {
		THROW(INVALID_INPUT, "Invalid input return_status_print.");
	}

	static const unsigned char success_string[] = "SUCCESS";
	static const unsigned char error_string[] = "ERROR\nerror stack trace:\n";
	static const unsigned char null_string[] = "(nullptr)";

	// count how much space needs to be allocated
	if (status_to_print->status == SUCCESS) {
		output_size += sizeof(success_string);
	} else {
		output_size += sizeof(error_string);

		// iterate over error stack
		for (error_message *current_error = status_to_print->error;
				current_error != nullptr;
				current_error = current_error->next) {

			output_size += sizeof("XXX: ");
			output_size += strlen(return_status_get_name(current_error->status));
			output_size += sizeof(", ");

			if (current_error->message == nullptr) {
				output_size += sizeof(null_string);
			} else {
				output_size += strlen(current_error->message);
			}

			output_size += sizeof('\n');
		}
	}

	output = buffer_create_on_heap(output_size, 0);
	THROW_on_failed_alloc(output);

	{
		int status_int = 0;
		// now fill the output
		if (status_to_print->status == SUCCESS) {
			if (output->cloneFromRaw(success_string, sizeof(success_string) - 1) != 0) {
				THROW(BUFFER_ERROR, "Failed to copy success_string.");
			}
		} else {
			if (output->cloneFromRaw(error_string, sizeof(error_string) - 1) != 0) {
				THROW(BUFFER_ERROR, "Failed to copy error_string.");
			}

			// iterate over error stack
			size_t i = 0;
			for (error_message *current_error = status_to_print->error;
					current_error != nullptr;
					current_error = current_error->next, i++) {

				int written = 0;
				written = snprintf(
					(char*) output->content + output->content_length, //current position in output
					output->getBufferLength() - output->content_length, //remaining length of output
					"%.3zu: ",
					i);
				if (written != (sizeof("XXX: ") - 1)) {
					THROW(INCORRECT_BUFFER_SIZE, "Failed to write to output buffer, probably too short.");
				}
				output->content_length += (unsigned int)written;

				status_int = output->copyFromRaw(
						output->content_length,
						(const unsigned char*)return_status_get_name(current_error->status),
						0,
						strlen(return_status_get_name(current_error->status)));
				if (status_int != 0) {
					THROW(BUFFER_ERROR, "Failed to copy status name to stack trace.");
				}

				status_int = output->copyFromRaw(
						output->content_length,
						(const unsigned char*) ", ",
						0,
						sizeof(", ") - 1);
				if (status_int != 0) {
					THROW(BUFFER_ERROR, "Failed to copy \", \" to stack trace.");
				}

				if (current_error->message == nullptr) {
					status_int = output->copyFromRaw(
							output->content_length,
							null_string,
							0,
							sizeof(null_string) - 1);
					if (status_int != 0) {
						THROW(BUFFER_ERROR, "Failed to copy \"(nullptr)\" to stack trace.");
					}
				} else {
					status_int = output->copyFromRaw(
							output->content_length,
							(const unsigned char*) current_error->message,
							0,
							strlen(current_error->message));
					if (status_int != 0) {
						THROW(BUFFER_ERROR, "Failed to copy error message to stack trace.");
					}
				}

				status_int = output->copyFromRaw(
						output->content_length,
						(const unsigned char*) "\n",
						0,
						1);
				if (status_int != 0) {
					THROW(BUFFER_ERROR, "Failed to copy newline to stack trace.");
				}
			}
		}
	}

	{
		int status_int = output->copyFromRaw(
				output->content_length,
				(const unsigned char*) "",
				0,
				sizeof(""));
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy null terminator to stack trace.");
		}
	}

cleanup:
	; // C programming language, I really really love you (not)
	char *output_string = nullptr;
	if (status.status != SUCCESS) {
		buffer_destroy_from_heap_and_null_if_valid(output);
	} else {
		output_string = (char*) output->content;
		if (length != nullptr) {
			*length = output->content_length;
		}
		free_and_null_if_valid(output);
	}

	return_status_destroy_errors(&status);

	return output_string;
}
