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

#include "utils.h"
#include "../lib/common.h"

void print_hex(Buffer& data) noexcept {
	static const size_t WIDTH = 30;
	//buffer for hex string
	const size_t hex_length = data.content_length * 2 + sizeof("");
	char *hex = (char*)malloc(hex_length);
	if (hex == NULL) {
		fprintf(stderr, "Failed to print hex data.");
		exit(EXIT_FAILURE);
	}

	if (sodium_bin2hex(hex, hex_length, data.content, data.content_length) == NULL) {
		fprintf(stderr, "Failed to print hex data.");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < hex_length; i++) {
		if ((WIDTH != 0) && ((i % WIDTH) == 0) && (i != 0)) {
			putchar('\n');
		} else if ((i % 2 == 0) && (i != 0)) {
			putchar(' ');
		}
		putchar(hex[i]);
	}

	putchar('\n');

	//cleanup
	free(hex);
}

void print_to_file(Buffer& data, const std::string& filename) noexcept {
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


return_status read_file(Buffer*& data, const std::string& filename) noexcept {
	return_status status = return_status_init();

	FILE *file = nullptr;

	data = nullptr;

	file = fopen(filename.c_str(), "r");
	THROW_on_failed_alloc(file);

	{
		//get the filesize
		fseek(file, 0, SEEK_END);
		size_t filesize = (size_t)ftell(file);
		fseek(file, 0, SEEK_SET);

		data = Buffer::create(filesize, filesize);
		THROW_on_failed_alloc(data);
		data->content_length = fread(data->content, 1, filesize, file);
		if (data->content_length != (size_t)filesize) {
			THROW(INCORRECT_DATA, "Read less data from file than filesize.");
		}
	}

cleanup:
	on_error {
		buffer_destroy_from_heap_and_null_if_valid(data);
	}

	if (file != nullptr) {
		fclose(file);
		file = nullptr;
	}

	return status;
}
