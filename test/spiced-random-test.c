/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/spiced-random.h"
#include "utils.h"
#include "tracing.h"

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
	throw_on_error(GENERIC_ERROR, "Failed to generate spiced random data of length 0.");

cleanup:
	buffer_destroy_from_heap(output1);
	buffer_destroy_from_heap(output2);

	if (status.status != SUCCESS) {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
