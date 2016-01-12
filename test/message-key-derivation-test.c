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

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status;

	//create buffers;
	buffer_t *chain_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);
	buffer_t *message_key = buffer_create_on_heap(crypto_auth_BYTES, crypto_auth_BYTES);

	//create random chain key
	status = buffer_fill_random(chain_key, chain_key->buffer_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create chain key. (%i)\n", status);
		goto cleanup;
	}

	//print first chain key
	printf("Chain key (%zu Bytes):\n", chain_key->content_length);
	print_hex(chain_key);
	putchar('\n');

	//derive message key from chain key
	status = derive_message_key(message_key, chain_key);
	buffer_clear(chain_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive message key. (%i)\n", status);
		goto cleanup;
	}

	//print message key
	printf("Message key (%zu Bytes):\n", message_key->content_length);
	print_hex(message_key);
	putchar('\n');

cleanup:
	buffer_destroy_from_heap(chain_key);
	buffer_destroy_from_heap(message_key);
	return status;
}
