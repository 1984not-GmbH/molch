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

#include "integration-utils.hpp"

#include <fstream>

std::vector<unsigned char> read_file(const std::string name) {
	std::ifstream filestream(name, std::ios_base::binary);
	if (!filestream.is_open()) {
		throw Exception("Failed to open file '" + name + "' for reading.");
	}

	filestream.seekg(0, std::ios_base::end);
	auto size{filestream.tellg()};
	if (size < 0) {
		throw Exception("Filesize i smaller than zero.");
	}

	filestream.seekg(0);

	std::vector<unsigned char> file(static_cast<size_t>(size), 0);
	filestream.read(reinterpret_cast<char*>(file.data()), size);

	return file;
}
