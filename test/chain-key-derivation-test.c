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

	return_status status = return_status_init();

	//buffer for derived chain keys
	buffer_t *next_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	//create random initial chain key
	buffer_t *last_chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	if (buffer_fill_random(last_chain_key, last_chain_key->buffer_length) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to create last chain key.");
	}

	//print first chain key
	printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(last_chain_key);
	putchar('\n');


	//derive a chain of chain keys
	unsigned int counter;
	for (counter = 1; counter <= 5; counter++) {
		status = derive_chain_key(next_chain_key, last_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

		//print the derived chain key
		printf("Chain key Nr. %i:\n", counter);
		print_hex(next_chain_key);
		putchar('\n');

		//check that chain keys are different
		if (buffer_compare(last_chain_key, next_chain_key) == 0) {
			throw(INCORRECT_DATA, "Derived chain key is identical.");
		}

		//move next_chain_key to last_chain_key
		if (buffer_clone(last_chain_key, next_chain_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

cleanup:
	buffer_destroy_from_heap(last_chain_key);
	buffer_destroy_from_heap(next_chain_key);

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
