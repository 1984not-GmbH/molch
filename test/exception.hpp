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

#ifndef LIB_EXCEPTION_H
#define LIB_EXCEPTION_H

#include <exception>
#include <ostream>
#include <deque>

#include "../lib/return-status.hpp"
#include "../lib/error.hpp"

namespace Molch {
	struct Exception : public std::exception {
		Error error;

		Exception(const Error& error);
		Exception(const status_type type, const char* message);
		Exception(const return_status status);

		virtual const char* what() const noexcept override;
		return_status toReturnStatus() const;
	};

	std::ostream& operator<<(std::ostream& stream, const Exception& exception);
}

#define TRY_WITH_RESULT(result, call) \
	auto&& result{call};\
	if (!result) {\
		throw Exception(result.error());\
	}

#define TRY_VOID(call)\
	{\
		TRY_WITH_RESULT(result, call)\
	}

#endif /* LIB_EXCEPTION_H */
