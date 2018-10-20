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

#include <algorithm>
#include <new>
#include <memory>
#include <iterator>
#include <sstream>

#include "exception.hpp"

namespace Molch {
	Exception::Exception(const Error& error) {
		this->error = error;
	}

	Exception::Exception(const status_type type, const char* message) {
		this->error = Error(type, message);
	}

	Exception::Exception(const return_status status) {
		this->error = Error(status.status, status.error);
	}

	const char* Exception::what() const noexcept {
		return this->error.message;
	}

	return_status Exception::toReturnStatus() const {
		auto status{success_status};
		status.status = error.type;
		status.error = error.message;

		return status;
	}

	std::ostream& operator<<(std::ostream& stream, const Exception& exception) {
		stream << "ERROR: ";
		stream << exception.error.message;
		return stream;
	}
}
