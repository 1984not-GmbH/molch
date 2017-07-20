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

#ifndef LIB_MOLCH_EXCEPTION_H
#define LIB_MOLCH_EXCEPTION_H

#include <exception>
#include <string>
#include <deque>
#include "common.h"

class MolchError {
public:
	status_type type;
	std::string message;

	MolchError();
	MolchError(const status_type type, const std::string& message);

	/*
	 * \return An error message allocated with malloc
	 */
	error_message* toErrorMessage();
};

class MolchException : public std::exception {
private:
	std::deque<MolchError> error_stack;

public:

	MolchException(const MolchError& error);
	MolchException(const status_type type, const std::string& message);

	virtual const char* what() const noexcept;

	MolchException& add(const MolchException& exception);
	MolchException& add(const MolchError& error);
	return_status toReturnStatus() const;
	std::string print() const;
};

#endif /* LIB_MOLCH_EXCEPTION_H */
