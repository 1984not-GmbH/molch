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

#include "../lib/header.h"
#include "utils.h"

int main(void) {
	//create buffers
	Buffer *our_public_ephemeral_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *header = nullptr;
	Buffer *extracted_public_ephemeral_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	return_status status = return_status_init();

	uint32_t message_number;
	uint32_t previous_message_number;

	if (sodium_init() == -1) {
		THROW(INIT_ERROR, "Failed to initialize libsodium.");
	}

	int status_int;
	//create ephemeral key
	status_int = buffer_fill_random(our_public_ephemeral_key, our_public_ephemeral_key->content_length);
	if (status_int != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to create our public ephemeral.");
	}
	printf("Our public ephemeral key (%zu Bytes):\n", our_public_ephemeral_key->content_length);
	print_hex(our_public_ephemeral_key);

	//message numbers
	message_number = 2;
	previous_message_number = 10;
	printf("Message number: %u\n", message_number);
	printf("Previous message number: %u\n", previous_message_number);
	putchar('\n');

	//create the header
	status = header_construct(
			&header,
			our_public_ephemeral_key,
			message_number,
			previous_message_number);
	THROW_on_error(CREATION_ERROR, "Failed to create header.");

	//print the header
	printf("Header (%zu Bytes):\n", header->content_length);
	print_hex(header);
	putchar('\n');

	//get data back out of the header again
	uint32_t extracted_message_number;
	uint32_t extracted_previous_message_number;
	status = header_extract(
			extracted_public_ephemeral_key,
			&extracted_message_number,
			&extracted_previous_message_number,
			header);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to extract data from header.");

	printf("Extracted public ephemeral key (%zu Bytes):\n", extracted_public_ephemeral_key->content_length);
	print_hex(extracted_public_ephemeral_key);
	printf("Extracted message number: %u\n", extracted_message_number);
	printf("Extracted previous message number: %u\n", extracted_previous_message_number);
	putchar('\n');

	//compare them
	if (buffer_compare(our_public_ephemeral_key, extracted_public_ephemeral_key) != 0) {
		THROW(INVALID_VALUE, "Public ephemeral keys don't match.");
	}
	printf("Public ephemeral keys match.\n");

	if (message_number != extracted_message_number) {
		THROW(INVALID_VALUE, "Message number doesn't match.");
	}
	printf("Message numbers match.\n");

	if (previous_message_number != extracted_previous_message_number) {
		THROW(INVALID_VALUE, "Previous message number doesn't match.");
	}
	printf("Previous message numbers match.\n");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(our_public_ephemeral_key);
	buffer_destroy_from_heap_and_null_if_valid(extracted_public_ephemeral_key);
	buffer_destroy_from_heap_and_null_if_valid(header);

	on_error {
		print_errors(&status);
		return_status_destroy_errors(&status);
	}

	return status.status;
}
