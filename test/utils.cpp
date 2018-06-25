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
#include <sodium.h>
#include <exception>
#include <fstream>
#include <limits>

#include "utils.hpp"
#include "../lib/destroyers.hpp"

using namespace Molch;

MOLCH_PUBLIC(void) print_to_file(const gsl::span<const std::byte> data, const std::string& filename) {
	std::ofstream filestream{filename, std::ios_base::out | std::ios_base::binary};
	if (!filestream.is_open()) {
		throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to open output file."};
	}

	filestream.exceptions(~std::ios_base::goodbit);

	if (data.size() > std::numeric_limits<std::streamsize>::max()) {
		throw Molch::Exception{status_type::GENERIC_ERROR, "The buffer size exceeds std::streamsize."};
	}
	filestream.write(reinterpret_cast<const char*>(data.data()), gsl::narrow<std::streamsize>(data.size()));
}

MOLCH_PUBLIC(void) print_errors(const return_status& status) {
	fprintf(stderr, "ERROR STACK:\n");
	error_message *error = status.error;
	for (size_t i{1}; error != nullptr; i++, error = error->next) {
		fprintf(stderr, "%zu: %s\n", i, error->message);
	}
}


MOLCH_PUBLIC(Buffer) read_file(const std::string& filename) {
	std::ifstream filestream{filename, std::ios_base::in | std::ios_base::binary};
	if (!filestream.is_open()) {
		throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to open file."};
	}

	filestream.exceptions(~std::ios_base::goodbit);

	//get the filesize
	filestream.seekg(0, std::ios_base::end);
	auto filesize{filestream.tellg()};
	if (filesize < 0) {
		throw Molch::Exception{status_type::GENERIC_ERROR, "Filesize is smaller than 0."};
	}
	if (filesize > std::numeric_limits<std::streamsize>::max()) {
		throw Molch::Exception{status_type::GENERIC_ERROR, "Filesize is larger than representable by std::streamsize."};
	}
	auto size{filesize};
	filestream.seekg(0);

	Buffer data{gsl::narrow_cast<size_t>(size), gsl::narrow_cast<size_t>(size)};
	filestream.read(reinterpret_cast<char*>(data.data()), gsl::narrow<std::streamsize>(filesize));

	return data;
}
