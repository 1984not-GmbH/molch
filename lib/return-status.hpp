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

#include "../include/molch/return-status.h"
#include "gsl.hpp"

namespace Molch {
	constexpr return_status success_status{status_type::SUCCESS, nullptr};

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

//Execute code on error
#define on_error if (status.status != status_type::SUCCESS)

#endif /* LIB_RETURN_STATUS_HPP */
