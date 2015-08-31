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

#include "../lib/buffer.h"
#include "utils.h"

int main(void) {
	sodium_init();

	//create a new buffer
	buffer_t *key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	randombytes_buf(key->content, key->content_length);

	printf("Random buffer (%zi Bytes):\n", key->content_length);
	print_hex(key->content, key->content_length, 30);
	putchar('\n');

	return EXIT_SUCCESS;
}
