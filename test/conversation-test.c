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
#include <string.h>
#include <assert.h>

#include "common.h"
#include "../lib/conversation.h"

int main(void) {
	int status = sodium_init();
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (%i)\n", status);
		return status;
	}

	//creating charlie's identity keypair
	buffer_t *charlie_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			buffer_create_from_string("charlie"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		return status;
	}

	//creating charlie's ephemeral keypair
	buffer_t *charlie_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			buffer_create_from_string("charlie"),
			buffer_create_from_string("ephemeral"));
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		return status;
	}

	//creating dora's identity keypair
	buffer_t *dora_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			buffer_create_from_string("dora"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		buffer_clear(dora_private_identity);
		return status;
	}

	//creating dora's ephemeral keypair
	buffer_t *dora_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			buffer_create_from_string("dora"),
			buffer_create_from_string("ephemeral"));
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		return status;
	}

	//create charlie's conversation
	conversation *charlie_conversation = conversation_create(
			charlie_private_identity,
			charlie_public_identity,
			dora_public_identity,
			charlie_private_ephemeral,
			charlie_public_ephemeral,
			dora_public_ephemeral);
	buffer_clear(charlie_private_identity);
	buffer_clear(charlie_private_ephemeral);
	if (charlie_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to create Charlie's conversation.\n");
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		return EXIT_FAILURE;
	}
	if (charlie_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Charlie's conversation has an incorrect ID length.\n");
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		conversation_destroy(charlie_conversation);
		return EXIT_FAILURE;
	}

	//create Dora's conversation
	conversation *dora_conversation = conversation_create(
			dora_private_identity,
			dora_public_identity,
			charlie_public_identity,
			dora_private_ephemeral,
			dora_public_ephemeral,
			charlie_public_ephemeral);
	buffer_clear(dora_private_identity);
	buffer_clear(dora_private_ephemeral);
	if (dora_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to create Dora's conversation.\n");
		conversation_destroy(charlie_conversation);
		return EXIT_FAILURE;
	}
	if (dora_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Dora's conversation has an incorrect ID length.\n");
		conversation_destroy(charlie_conversation);
		conversation_destroy(dora_conversation);
		return EXIT_FAILURE;
	}

	//now destroy the conversations again
	conversation_destroy(charlie_conversation);
	conversation_destroy(dora_conversation);
}
