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

#include "return-status.hpp"
#include "error.hpp"

namespace Molch {
	class Exception : public std::exception {
	private:
		std::deque<Error> error_stack;
		mutable std::string printed;

	public:

		Exception(const Error& error);
		Exception(const status_type type, const std::string& message);
		Exception(return_status& status);

		virtual const char* what() const noexcept override;

		Exception& add(const Exception& exception);
		Exception& add(const Error& error);
		return_status toReturnStatus() const;
		std::ostream& print(std::ostream& stream) const;
	};

	//throw std::bad_alloc if something is nullptr
	template <typename T>
	inline void exception_on_failed_alloc(const T* const& object) {
		if (object == nullptr) {
			throw std::bad_alloc();
		}
	}
}

#endif /* LIB_EXCEPTION_H */
