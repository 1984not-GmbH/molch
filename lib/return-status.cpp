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
#include <algorithm>
#include <new>
#include <memory>
#include <exception>
#include <sstream>

#include "return-status.h"
#include "buffer.hpp"
#include "destroyers.hpp"
#include "molch-exception.hpp"
#include "malloc.hpp"

using namespace Molch;

extern return_status return_status_init() noexcept {
	return_status status = {
		SUCCESS,
		nullptr
	};
	return status;
}

status_type return_status_add_error_message(
		return_status *const status_object,
		const char *const message,
		const status_type status_to_add) noexcept {

	if (status_object == nullptr) {
		return INVALID_INPUT;
	}

	if (message == nullptr) {
		return SUCCESS;
	}

	std::unique_ptr<error_message> error;
	std::unique_ptr<char> copied_message;
	size_t message_length = strlen(message) + sizeof("");

	// allocate the memory
	try {
		error = std::make_unique<error_message>();
		copied_message = std::unique_ptr<char>(new char[message_length]);
	} catch (const std::bad_alloc& exception) {
		return ALLOCATION_FAILED;
	}

	error->message = copied_message.release();
	std::copy(message, message + message_length, error->message);

	error->next = status_object->error;
	error->status = status_to_add;

	status_object->error = error.release();
	status_object->status = status_to_add;

	return SUCCESS;
}

void return_status_destroy_errors(return_status * const status) noexcept {
	if (status == nullptr) {
		return;
	}

	while (status->error != nullptr) {
		error_message *next_error = status->error->next;

		delete[] status->error->message;
		delete status->error;

		status->error = next_error;
	}
}

/*
 * Get the name of a status type as a string.
 */
const char *return_status_get_name(status_type status) noexcept {
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

		case EXCEPTION:
			return "EXCEPTION";

		default:
			return "(nullptr)";
	}
}

/*
 * Pretty print the error stack into a buffer.
 *
 * Don't forget to free with "free" after usage.
 */
char *return_status_print(const return_status * const status_to_print, size_t *length) noexcept {
	std::stringstream stream;
	//Buffer output;
	try {
		//check input
		if (status_to_print == nullptr) {
			throw MolchException(INVALID_INPUT, "Invalid input return_status_print.");
		}

		static const unsigned char success_string[] = "SUCCESS";
		static const unsigned char error_string[] = "ERROR\nerror stack trace:\n";
		static const unsigned char null_string[] = "(nullptr)";

		// now fill the output
		if (status_to_print->status == SUCCESS) {
			stream << success_string;
		} else {
			stream << error_string;

			// iterate over error stack
			size_t i = 0;
			for (error_message *current_error = status_to_print->error;
					current_error != nullptr;
					current_error = current_error->next, i++) {

				stream << i << ": ";
				stream << return_status_get_name(current_error->status);
				stream << ", ";

				if (current_error->message == nullptr) {
					stream << null_string;
				} else {
					stream << current_error->message;
				}

				stream << std::endl;
			}
		}

		//Copy the string to the output
		//TODO Stream directly to malloced vector of unsigned char?
		auto output_string = stream.str();
		auto output_ptr = std::unique_ptr<char,MallocDeleter<char>>(throwing_malloc<char>(output_string.size() + sizeof("")));
		std::copy(output_string.data(), output_string.data() + output_string.size() + sizeof(""), output_ptr.get());

		*length = output_string.size() + sizeof("");
		return output_ptr.release();
	} catch (const std::exception& exception) {
		if (length != nullptr) {
			*length = 0;
		}
		return nullptr;
	}

	/*if (output.isNone()) {
		if (length != nullptr) {
			*length = 0;
		}
		return nullptr;
	}*/

	/*char *output_string = nullptr;
	if (length != nullptr) {
		*length = output.size;
	}*/
	//output_string = reinterpret_cast<char*>(output.release());

	//return output_string;
}
