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

#include "error.hpp"

namespace Molch {
	Error::Error() :
		type{status_type::SUCCESS},
		message{""} {}

	Error::Error(const status_type type, const std::string& message) :
		type{type},
		message{message} {}

	error_message* Error::toErrorMessage() {
		std::unique_ptr<error_message> error;
		std::unique_ptr<char[]> copied_message;

		//allocate memory
		try {
			error = std::make_unique<error_message>();
			copied_message = std::make_unique<char[]>(message.length() + sizeof(""));
		} catch (const std::bad_alloc&) {
			return nullptr;
		}

		error->message = nullptr;
		error->next = nullptr;

		// copy the message if it isn't empty
		if (!this->message.empty()) {
			error->message = copied_message.release();

			this->message.copy(error->message, this->message.length());
			error->message[this->message.length()] = '\0';
		}

		return error.release();
	}

}
