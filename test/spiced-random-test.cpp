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

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/spiced-random.h"
#include "utils.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//some random user input (idiot bashing his head on the keyboard)
	buffer_create_from_string(spice, "aäipoewur+ü 093+2ß3+2ü+ ß09234rt #2ß 0iw4eräp9ui23+ 03943");
	printf("\"Random\" input from the user (%zu Bytes):\n", spice->content_length);
	printf("String: %s\n", spice->content);
	printf("Hex:\n");
	print_hex(spice);
	putchar('\n');

	//output buffers
	buffer_t *output1 = buffer_create_on_heap(42, 0);
	buffer_t *output2 = buffer_create_on_heap(42, 0);

	//fill buffer with spiced random data
	status = spiced_random(output1, spice, output1->buffer_length);
	throw_on_error(GENERIC_ERROR, "Failed to generate spiced random data.");

	printf("Spiced random data 1 (%zu Bytes):\n", output1->content_length);
	print_hex(output1);
	putchar('\n');


	//fill buffer with spiced random data
	status = spiced_random(output2, spice, output2->buffer_length);
	throw_on_error(GENERIC_ERROR, "Failed to generate spiced random data.");

	printf("Spiced random data 2 (%zu Bytes):\n", output2->content_length);
	print_hex(output2);
	putchar('\n');

	//compare the two (mustn't be identical!)
	if (buffer_compare(output1, output2) == 0) {
		throw(INCORRECT_DATA, "Random numbers aren't random.");
	}

	//don't crash with output length 0
	status = spiced_random(output1, spice, 0);
	on_error {
		//on newer libsodium versions, output lengths of zero aren't supported
		return_status_destroy_errors(&status);
		status.status = SUCCESS;
	}

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(output1);
	buffer_destroy_from_heap_and_null_if_valid(output2);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
