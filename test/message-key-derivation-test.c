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
	sodium_init();

	int status;
	//create random chain key
	buffer_t *chain_key = buffer_create(crypto_auth_BYTES, crypto_auth_BYTES);
	status = buffer_fill_random(chain_key, chain_key->buffer_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create chain key. (%i)\n", status);
		buffer_clear(chain_key);
		return status;
	}

	//print first chain key
	printf("Chain key (%zi Bytes):\n", chain_key->content_length);
	print_hex(chain_key->content, chain_key->content_length, 30);
	putchar('\n');

	//derive message key from chain key
	buffer_t *message_key = buffer_create(crypto_auth_BYTES, crypto_auth_BYTES);
	status = derive_message_key(message_key, chain_key);
	buffer_clear(chain_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive message key. (%i)\n", status);
		buffer_clear(message_key);
		return status;
	}

	//print message key
	printf("Message key (%zi Bytes):\n", message_key->content_length);
	print_hex(message_key->content, message_key->content_length, 30);
	putchar('\n');

	buffer_clear(message_key);
	return EXIT_SUCCESS;
}
