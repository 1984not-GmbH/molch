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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <exception>

#include "utils.hpp"
#include "../lib/destroyers.hpp"
#include "../lib/molch-exception.hpp"

void print_to_file(const Buffer& data, const std::string& filename) noexcept {
	FILE *file = fopen(filename.c_str(), "w");
	if (file == nullptr) {
		return;
	}

	fwrite(data.content, 1, data.content_length, file);

	fclose(file);
}

void print_errors(const return_status& status) noexcept {
	fprintf(stderr, "ERROR STACK:\n");
	error_message *error = status.error;
	for (size_t i = 1; error != nullptr; i++, error = error->next) {
		fprintf(stderr, "%zu: %s\n", i, error->message);
	}
}


std::unique_ptr<Buffer> read_file(const std::string& filename) {
	FILE *file = nullptr;

	file = fopen(filename.c_str(), "r");
	if (file == nullptr) {
		throw MolchException(GENERIC_ERROR, "Failed to open file.");
	}

	//get the filesize
	fseek(file, 0, SEEK_END);
	size_t filesize = static_cast<size_t>(ftell(file));
	fseek(file, 0, SEEK_SET);

	auto data = std::make_unique<Buffer>(filesize, filesize);
	data->content_length = fread(data->content, 1, filesize, file);
	fclose(file);
	file = nullptr;
	if (data->content_length != filesize) {
		throw MolchException(INCORRECT_DATA, "Read less data from file than filesize.");
	}

	return data;
}
