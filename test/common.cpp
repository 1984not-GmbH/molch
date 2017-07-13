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

#include "common.h"
#include "utils.h"

/*
 * Print a header and message keystore with all of it's entries.
 */
void print_header_and_message_keystore(header_and_message_keystore *keystore) {
	printf("KEYSTORE-START-----------------------------------------------------------------\n");
	printf("Length: %zu\n", keystore->length);
	printf("Head: %p\n", (void*) keystore->head);
	printf("Tail: %p\n\n", (void*) keystore->tail);

	header_and_message_keystore_node* node = keystore->head;

	//print all the keys in the keystore
	for (size_t i = 0; i < keystore->length; node = node->next, i++) {
		printf("Header key %zu:\n", i);
		print_hex(node->header_key);
		putchar('\n');

		printf("Message key %zu:\n", i);
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
return_status generate_and_print_keypair(
		Buffer * const public_key, //crypto_box_PUBLICKEYBYTES
		Buffer * const private_key, //crypto_box_SECRETKEYBYTES
		Buffer * name, //Name of the key owner (e.g. "Alice")
		Buffer * type) { //type of the key (e.g. "ephemeral")
	return_status status = return_status_init();

	//check buffer sizes
	if ((public_key->getBufferLength() < crypto_box_PUBLICKEYBYTES)
			|| (private_key->getBufferLength() < crypto_box_SECRETKEYBYTES)) {
		THROW(INCORRECT_BUFFER_SIZE, "Public key buffer is too short.");
	}
	//generate keypair
	{
		int status_int = 0;
		status_int = crypto_box_keypair(public_key->content, private_key->content);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate keypair.");
		}
	}
	public_key->content_length = crypto_box_PUBLICKEYBYTES;
	private_key->content_length = crypto_box_SECRETKEYBYTES;

	//print keypair
	printf("%.*s's public %.*s key (%zu Bytes):\n", (int)name->content_length, name->content, (int)type->content_length, type->content, public_key->content_length);
	print_hex(public_key);
	putchar('\n');
	printf("%.*s's private %.*s key (%zu Bytes):\n", (int)name->content_length, name->content, (int)type->content_length, type->content, private_key->content_length);
	print_hex(private_key);
	putchar('\n');

cleanup:
	return status;
}
