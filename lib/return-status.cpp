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

#include "return-status.hpp"
#include "buffer.hpp"
#include "destroyers.hpp"
#include "malloc.hpp"
#include "gsl.hpp"

namespace Molch {
	/*
	 * Get the name of a status type as a string.
	 */
	const char *return_status_get_name(status_type status) noexcept {
		switch (status) {
			case status_type::SUCCESS:
				return "SUCCESS";

			case status_type::GENERIC_ERROR:
				return "GENERIC_ERROR";

			case status_type::INVALID_VALUE:
				return "INVALID_VALUE";

			case status_type::INCORRECT_BUFFER_SIZE:
				return "INCORRECT_BUFFER_SIZE";

			case status_type::BUFFER_ERROR:
				return "BUFFER_ERROR";

			case status_type::INCORRECT_DATA:
				return "INCORRECT_DATA";

			case status_type::INIT_ERROR:
				return "INIT_ERROR";

			case status_type::ALLOCATION_FAILED:
				return "ALLOCATION_FAILED";

			case status_type::NOT_FOUND:
				return "NOT_FOUND";

			case status_type::VERIFICATION_FAILED:
				return "VERIFICATION_FAILED";

			case status_type::EXPORT_ERROR:
				return "EXPORT_ERROR";

			case status_type::IMPORT_ERROR:
				return "IMPORT_ERROR";

			case status_type::KEYGENERATION_FAILED:
				return "KEYGENERATION_FAILED";

			case status_type::KEYDERIVATION_FAILED:
				return "KEYDERIVATION_FAILED";

			case status_type::SEND_ERROR:
				return "SEND_ERROR";

			case status_type::RECEIVE_ERROR:
				return "RECEIVE_ERROR";

			case status_type::DATA_FETCH_ERROR:
				return "DATA_FETCH_ERROR";

			case status_type::DATA_SET_ERROR:
				return "DATA_SET_ERROR";

			case status_type::ENCRYPT_ERROR:
				return "ENCRYPT_ERROR";

			case status_type::DECRYPT_ERROR:
				return "DECRYPT_ERROR";

			case status_type::CONVERSION_ERROR:
				return "CONVERSION_ERROR";

			case status_type::SIGN_ERROR:
				return "SIGN_ERROR";

			case status_type::VERIFY_ERROR:
				return "VERIFY_ERROR";

			case status_type::REMOVE_ERROR:
				return "REMOVE_ERROR";

			case status_type::SHOULDNT_HAPPEN:
				return "SHOULDNT_HAPPEN";

			case status_type::INVALID_STATE:
				return "INVALID_STATE";

			case status_type::OUTDATED:
				return "OUTDATED";

			case status_type::PROTOBUF_PACK_ERROR:
				return "PROTOBUF_PACK_ERROR";

			case status_type::PROTOBUF_UNPACK_ERROR:
				return "PROTOBUF_UNPACK_ERROR";

			case status_type::PROTOBUF_MISSING_ERROR:
				return "PROTOBUF_MISSING_ERROR";

			case status_type::UNSUPPORTED_PROTOCOL_VERSION:
				return "UNSUPPORTED_PROTOCOL_VERSION";

			case status_type::EXCEPTION:
				return "EXCEPTION";

			case status_type::EXPECTATION_FAILED:
				return "EXPECTATION_FAILED";

			default:
				return "(nullptr)";
		}
	}

	/*
	 * Pretty print the error stack into a buffer.
	 *
	 * Don't forget to free with "free" after usage.
	 */
	span<char> return_status_print(const return_status& status) noexcept {
		try {
			std::stringstream stream;
			static const unsigned char success_string[]{"SUCCESS"};
			static const unsigned char error_string[]{"ERROR: "};
			static const unsigned char null_string[]{"(nullptr)"};

			// now fill the output
			if (status.status == status_type::SUCCESS) {
				stream << success_string;
			} else {
				stream << error_string;

				if (status.error == nullptr) {
					stream << null_string;
				} else {
					stream << status.error;
				}

				stream << '\n';
			}

			//Copy the string to the output
			//TODO Stream directly to malloced vector of unsigned char?
			auto output_string{stream.str()};
			auto output_ptr{std::unique_ptr<char,MallocDeleter<char>>(throwing_malloc<char>(output_string.size() + sizeof("")))};
			std::copy(output_string.data(), output_string.data() + output_string.size() + sizeof(""), output_ptr.get());

			return {output_ptr.release(), output_string.size() + sizeof("")};
		} catch (const std::exception&) {
			return {nullptr, static_cast<size_t>(0)};
		}
	}
}
