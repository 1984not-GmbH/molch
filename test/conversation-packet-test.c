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
#include "utils.h"
#include "../lib/conversation.h"

int main(void) {
	int status = sodium_init();
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (%i)\n", status);
		return status;
	}

	//create buffers
	//alice' keys
	buffer_t *alice_private_identity = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *alice_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *alice_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *alice_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//bobs keys
	buffer_t *bob_private_identity = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *bob_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	buffer_t *packet = NULL;
	buffer_t *received_message = NULL;

	//create keys
	//alice
	buffer_create_from_string(alice_string, "Alice");
	//identity
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate keys! (%i)\n", status);
		goto cleanup;
	}
	//ephemeral
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate keys! (%i)\n", status);
		goto cleanup;
	}
	//bob
	buffer_create_from_string(bob_string, "Bob");
	//identity
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			bob_string,
			identity_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate keys! (%i)\n", status);
		goto cleanup;
	}
	//ephemeral
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			bob_string,
			ephemeral_string);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate keys! (%i)\n", status);
		goto cleanup;
	}

	//start a send conversation
	buffer_create_from_string(send_message, "Hello there!");
	conversation_t alice_send_conversation;
	status = conversation_start_send_conversation(
			&alice_send_conversation,
			send_message,
			&packet,
			alice_public_identity,
			alice_private_identity,
			alice_public_ephemeral,
			alice_private_ephemeral,
			bob_public_identity,
			bob_public_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to send message.\n");
		goto cleanup;
	}
	conversation_deinit(&alice_send_conversation);
	printf("Sent message: %.*s\n", (int)send_message->content_length, (const char*)send_message->content);
	printf("Packet:\n");
	print_hex(packet);
	putchar('\n');

	//let bob receive the packet
	conversation_t bob_receive_conversation;
	status = conversation_start_receive_conversation(
			&bob_receive_conversation,
			packet,
			&received_message,
			alice_public_identity,
			alice_public_ephemeral,
			bob_public_identity,
			bob_private_identity,
			bob_public_ephemeral,
			bob_private_ephemeral);
	conversation_deinit(&bob_receive_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt received message. (%i)\n", status);
		goto cleanup;
	}

	status = buffer_compare(send_message, received_message);
	if (status != 0) {
		fprintf(stderr, "ERROR: Incorrect message decrypted. (%i)\n", status);
		goto cleanup;
	}
	printf("Decrypted message matches with the original message.\n");


	//now test it the other way round (because Axolotl is assymetric in this regard)
	//Bob sends the message to Alice.
	conversation_t bob_send_conversation;
	//destroy the old packet
	buffer_destroy_from_heap(packet);
	packet = NULL;
	status = conversation_start_send_conversation(
			&bob_send_conversation,
			send_message,
			&packet,
			bob_public_identity,
			bob_private_identity,
			bob_public_ephemeral,
			bob_private_ephemeral,
			alice_public_identity,
			alice_public_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to send message. (%i)\n", status);
		goto cleanup;
	}
	conversation_deinit(&bob_send_conversation);
	printf("Sent message: %.*s\n", (int)send_message->content_length, (const char*)send_message->content);
	printf("Packet:\n");
	print_hex(packet);
	putchar('\n');

	//let alice receive the packet
	conversation_t alice_receive_conversation;
	buffer_destroy_from_heap(received_message);
	received_message = NULL;
	status = conversation_start_receive_conversation(
			&alice_receive_conversation,
			packet,
			&received_message,
			bob_public_identity,
			bob_public_ephemeral,
			alice_public_identity,
			alice_private_identity,
			alice_public_ephemeral,
			alice_private_ephemeral);
	conversation_deinit(&alice_receive_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt received message. (%i)\n", status);
		goto cleanup;
	}

	status = buffer_compare(send_message, received_message);
	if (status != 0) {
		fprintf(stderr, "ERROR: Incorrect message decrypted. (%i)\n", status);
		goto cleanup;
	}
	printf("Decrypted message matched with the original message.\n");

cleanup:
	if (packet != NULL) {
		buffer_destroy_from_heap(packet);
	}
	if (received_message != NULL) {
		buffer_destroy_from_heap(received_message);
	}
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(alice_public_ephemeral);
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(bob_public_ephemeral);

	return status;
}
