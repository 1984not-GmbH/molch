/*  Molch, an implementation of the axolotl ratchet based on libsodium
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

#include "common.h"
#include "utils.h"

/*
 * Print a header and message keystore with all of it's entries.
 */
void print_header_and_message_keystore(header_and_message_keystore *keystore) {
	printf("KEYSTORE-START-----------------------------------------------------------------\n");
	printf("Length: %i\n", keystore->length);
	printf("Head: %p\n", (void*) keystore->head);
	printf("Tail: %p\n\n", (void*) keystore->tail);

	header_and_message_keystore_node* node = keystore->head;

	//print all the keys in the keystore
	unsigned int i;
	for (i = 0; i < keystore->length; node = node->next, i++) {
		printf("Header key %u:\n", i);
		print_hex(node->header_key);
		putchar('\n');

		printf("Message key %u:\n", i);
		print_hex(node->message_key);
		if (i != keystore->length - 1) { //omit last one
			putchar('\n');
		}
	}
	puts("KEYSTORE-END-------------------------------------------------------------------\n");
}

/*
 * Generates and prints a crypto_box keypair.
 */
int generate_and_print_keypair(
		buffer_t * const public_key, //crypto_box_PUBLICKEYBYTES
		buffer_t * const private_key, //crypto_box_SECRETKEYBYTES
		const buffer_t * name, //Name of the key owner (e.g. "Alice")
		const buffer_t * type) { //type of the key (e.g. "ephemeral")
	//check buffer sizes
	if ((public_key->buffer_length < crypto_box_PUBLICKEYBYTES)
			|| (private_key->buffer_length < crypto_box_SECRETKEYBYTES)) {
		return -6;
	}
	//generate keypair
	int status = crypto_box_keypair(public_key->content, private_key->content);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate %.*s's %.*s keypair. (%i)\n", (int)name->content_length, name->content, (int)type->content_length, type->content, status);
		return status;
	}
	public_key->content_length = crypto_box_PUBLICKEYBYTES;
	private_key->content_length = crypto_box_SECRETKEYBYTES;

	//print keypair
	printf("%.*s's public %.*s key (%zi Bytes):\n", (int)name->content_length, name->content, (int)type->content_length, type->content, public_key->content_length);
	print_hex(public_key);
	putchar('\n');
	printf("%.*s's private %.*s key (%zi Bytes):\n", (int)name->content_length, name->content, (int)type->content_length, type->content, private_key->content_length);
	print_hex(private_key);
	putchar('\n');

	return 0;
}
