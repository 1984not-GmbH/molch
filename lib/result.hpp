/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 1984not Security GmbH
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

#ifndef LIB_RESULT_HPP
#define LIB_RESULT_HPP

//FIXME: This is a workaround for a clang compile error when including Boost.Outcome before Protobuf
#include "protobuf-arena.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wswitch-default"
#pragma GCC diagnostic ignored "-Wmissing-noreturn"
#include <outcome.hpp>
#pragma GCC diagnostic pop

#include "error.hpp"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace Molch {
	template <typename Result>
	using result = outcome::result<Result,Error>;
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

#define FulfillOrFailWithLine(condition, line)\
	if (!(condition)) {\
		return Error(status_type::EXPECTATION_FAILED, "An expectation failed in line " #line " of file " __FILE__);\
	}

#define FulfillOrFail(condition) FulfillOrFailWithLine(condition, __LINE__)

#endif /* LIB_RESULT_HPP */
