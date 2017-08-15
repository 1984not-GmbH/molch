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

#include "molch-exception.hpp"

MolchError::MolchError() {
	this->type = SUCCESS;
	this->message = "";
}

MolchError::MolchError(const status_type type, const std::string& message) {
	this->type = type;
	this->message = message;
}

error_message* MolchError::toErrorMessage() {
	std::unique_ptr<error_message> error;
	std::unique_ptr<char> copied_message;

	//allocate memory
	try {
		error = std::unique_ptr<error_message>(new error_message);
		copied_message = std::unique_ptr<char>(new char[message.length() + sizeof("")]);
	} catch (const std::bad_alloc& exception) {
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

MolchException::MolchException(const MolchError& error) {
	this->add(error);
}

MolchException::MolchException(const status_type type, const std::string& message) {
	this->error_stack.push_front(MolchError(type, message));
}

MolchException::MolchException(return_status& status) {
	error_message *error = status.error;
	while (error != nullptr) {
		this->error_stack.push_back(MolchError(error->status, error->message));
	}

	return_status_destroy_errors(&status);
}

const char* MolchException::what() const noexcept {
	static const char* what = "MolchException";
	return what;
}

MolchException& MolchException::add(const MolchException& exception) {
	for (auto&& error : exception.error_stack) {
		this->error_stack.push_back(error);
	}

	return *this;
}

MolchException& MolchException::add(const MolchError& error) {
	this->error_stack.push_front(error);

	return *this;
}

return_status MolchException::toReturnStatus() const {
	return_status status = return_status_init();

	// add the error messages in reverse order
	for (auto&& error = std::crbegin(this->error_stack); error != std::crend(this->error_stack); ++error) {
		status_type add_status = return_status_add_error_message(&status, error->message.c_str(), error->type);
		if (add_status != SUCCESS) {
			return_status_destroy_errors(&status);
			status.status = add_status;
			return status;
		}
	}

	return status;
}

std::ostream& MolchException::print(std::ostream& stream) const {
	stream << "ERROR\nerror stack trace:\n";

	size_t i = 0;
	for (const auto& error : this->error_stack) {
		stream << i << ": " << return_status_get_name(error.type) << ", " << error.message << '\n';
		i++;
	}

	return stream;
}
