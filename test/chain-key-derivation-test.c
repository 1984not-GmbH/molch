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
#include <string.h>
#include <sodium.h>

#include "../lib/key-derivation.h"
#include "utils.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status;

	//buffer for derived chain keys
	buffer_t *next_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	//create random initial chain key
	buffer_t *last_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	status = buffer_fill_random(last_chain_key, last_chain_key->buffer_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create last chain key. (%i)\n", status);
		goto cleanup;
	}

	//print first chain key
	printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(last_chain_key);
	putchar('\n');


	//derive a chain of chain keys
	unsigned int counter;
	for (counter = 1; counter <= 5; counter++) {
		status = derive_chain_key(next_chain_key, last_chain_key);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to derive chain key %i. (%i)\n", counter, status);
			goto cleanup;
		}

		//print the derived chain key
		printf("Chain key Nr. %i:\n", counter);
		print_hex(next_chain_key);
		putchar('\n');

		//check that chain keys are different
		status = buffer_compare(last_chain_key, next_chain_key);
		if (status == 0) {
			fprintf(stderr, "ERROR: Derived chain key is identical. (%i)\n", status);
			status = -5;
			goto cleanup;
		}

		//move next_chain_key to last_chain_key
		status = buffer_clone(last_chain_key, next_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	buffer_destroy_from_heap(last_chain_key);
	buffer_destroy_from_heap(next_chain_key);
	return status;
}
