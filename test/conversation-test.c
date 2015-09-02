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

#include "../lib/conversation.h"
#include "utils.h"
#include "common.h"

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
	ratchet_state *charlie_conversation = conversation_create(
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

	//create Dora's conversation
	ratchet_state *dora_conversation = conversation_create(
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
		return EXIT_FAILURE;
	}

	//--------------------------------------------------------------------------
	//charlie writes two messages to dora
	//message 1
	buffer_t *charlie_send_message1 = buffer_create_from_string("Hi Dora.");
	buffer_t *charlie_send_ciphertext1 = buffer_create(362 + charlie_send_message1->content_length, 0);
	status = conversation_send_message(
			charlie_send_ciphertext1,
			charlie_send_message1,
			charlie_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt Charlie's first message. (%i)\n", status);
		buffer_clear(charlie_send_message1);
		return status;
	}

	printf("Charlie's first message (%zi Bytes):\n%.*s\n", charlie_send_message1->content_length, (int)charlie_send_message1->content_length, charlie_send_message1->content);
	printf("Ciphertext of Charlie's first message (%zi):\n", charlie_send_ciphertext1->content_length);
	print_hex(charlie_send_ciphertext1);
	putchar('\n');

	//message 2
	buffer_t *charlie_send_message2 = buffer_create_from_string("How are you doing?");
	buffer_t *charlie_send_ciphertext2 = buffer_create(362 + charlie_send_message2->content_length, 0);
	status = conversation_send_message(
			charlie_send_ciphertext2,
			charlie_send_message2,
			charlie_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt Charlie's second message. (%i)\n", status);
		buffer_clear(charlie_send_message1);
		buffer_clear(charlie_send_message2);
		return status;
	}

	printf("Charlie's second message (%zi Bytes):\n%.*s\n", charlie_send_message2->content_length, (int)charlie_send_message2->content_length, charlie_send_message2->content);
	printf("Ciphertext of Charlie's first message (%zi):\n", charlie_send_ciphertext2->content_length);
	print_hex(charlie_send_ciphertext2);
	putchar('\n');

	//--------------------------------------------------------------------------
	//dora receives the two messages
	//message 1
	buffer_t *dora_receive_message1 = buffer_create(charlie_send_ciphertext1->content_length - 100, 0);
	status = conversation_receive_message(
			dora_receive_message1,
			charlie_send_ciphertext1,
			dora_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt Charlie's first message. (%i)\n", status);
		buffer_clear(dora_receive_message1);
		buffer_clear(charlie_send_message1);
		buffer_clear(charlie_send_message2);
		return status;
	}
	printf("First decrypted message (%zi):\n%.*s\n", dora_receive_message1->content_length, (int)dora_receive_message1->content_length, dora_receive_message1->content);

	//compare message 1
	if (buffer_compare(charlie_send_message1, dora_receive_message1) != 0) {
		fprintf(stderr, "ERROR: First message didn't match.\n");
		buffer_clear(dora_receive_message1);
		buffer_clear(charlie_send_message1);
		buffer_clear(charlie_send_message2);
		return EXIT_FAILURE;
	}
	printf("First message matches.\n");
	buffer_clear(dora_receive_message1);
	buffer_clear(charlie_send_message1);

	//message 2
	buffer_t *dora_receive_message2 = buffer_create(charlie_send_ciphertext2->content_length - 100, 0);
	status = conversation_receive_message(
			dora_receive_message2,
			charlie_send_ciphertext2,
			dora_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt Charlie's second message. (%i)\n", status);
		buffer_clear(dora_receive_message2);
		buffer_clear(charlie_send_message2);
		return status;
	}

	//compare message 1
	if (buffer_compare(charlie_send_message2, dora_receive_message2) != 0) {
		fprintf(stderr, "ERROR: First message didn't match.\n");
		buffer_clear(dora_receive_message2);
		buffer_clear(charlie_send_message2);
		return EXIT_FAILURE;
	}
	printf("First message matches.\n");
	buffer_clear(dora_receive_message2);
	buffer_clear(charlie_send_message2);

	return EXIT_SUCCESS;
}
