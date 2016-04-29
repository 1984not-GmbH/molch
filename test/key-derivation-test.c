/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
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

#include "../lib/key-derivation.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//create buffers
	buffer_t *master_key = buffer_create_on_heap(50, 50);
	buffer_t *subkey1 = buffer_create_on_heap(60, 60);
	buffer_t *subkey2 = buffer_create_on_heap(60, 60);
	buffer_t *subkey1_copy = buffer_create_on_heap(60, 60);

	int status_int = 0;
	status_int = buffer_fill_random(master_key, master_key->buffer_length);
	if (status_int != 0) {
		throw(KEYDERIVATION_FAILED, "Failed to generate master key.");
	}
	printf("Master key:\n");
	print_hex(master_key);
	putchar('\n');

	status = derive_key(subkey1, subkey1->buffer_length, master_key, 0);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive first subkey.");
	printf("First subkey:\n");
	print_hex(subkey1);
	putchar('\n');

	status = derive_key(subkey2, subkey2->buffer_length, master_key, 1);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive the second subkey.");
	printf("Second subkey:\n");
	print_hex(subkey2);
	putchar('\n');

	if (buffer_compare(subkey1, subkey2) == 0) {
		throw(KEYGENERATION_FAILED, "Both subkeys are the same.");
	}

	status = derive_key(subkey1_copy, subkey1_copy->buffer_length, master_key, 0);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive copy of the first subkey.");

	if (buffer_compare(subkey1, subkey1_copy) != 0) {
		throw(INCORRECT_DATA, "Failed to reproduce subkey.");
	}

cleanup:
	buffer_destroy_from_heap(master_key);
	buffer_destroy_from_heap(subkey1);
	buffer_destroy_from_heap(subkey2);
	buffer_destroy_from_heap(subkey1_copy);

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
