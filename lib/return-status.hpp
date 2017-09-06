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

#ifndef LIB_RETURN_STATUS_HPP
#define LIB_RETURN_STATUS_HPP

#include "return-status.h"
#include "gsl.hpp"

namespace Molch {
	return_status return_status_init(void) noexcept;

	status_type return_status_add_error_message(
			return_status& status_object,
			const char *const message,
			const status_type status) noexcept __attribute__((warn_unused_result));

	void return_status_destroy_errors(return_status& status) noexcept;

	/*
	 * Get the name of a status type as a string.
	 */
	const char *return_status_get_name(status_type status) noexcept;

	/*
	 * Pretty print the error stack into a buffer.
	 *
	 * Don't forget to free with "free" after usage.
	 */
	span<char> return_status_print(const return_status& status) noexcept __attribute__((warn_unused_result));
}

//This assumes that there is a return_status struct and there is a "cleanup" label to jump to.
#define THROW(status_type_value, message) {\
	status.status = status_type_value;\
	if (message != nullptr) {\
		status_type THROW_type = return_status_add_error_message(status, message, status_type_value);\
		if (THROW_type != status_type::SUCCESS) {\
			status.status = THROW_type;\
		} else {\
			status.status = status_type::SHOULDNT_HAPPEN; /*I hope this makes clang analyzer accept my code!*/\
		}\
	} else {\
		status.error = nullptr;\
	}\
\
	goto cleanup;\
}

//Execute code on error
#define on_error if (status.status != status_type::SUCCESS)

#define THROW_on_error(status_type_value, message) on_error{THROW(status_type_value, message)}

#endif /* LIB_RETURN_STATUS_HPP */
