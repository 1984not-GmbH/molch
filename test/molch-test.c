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

#include "utils.h"
#include "../lib/molch.h"
#include "../lib/user-store.h" //for PREKEY_AMOUNT

int main(void) {
	sodium_init();

	//mustn't crash here!
	molch_destroy_all_users();

	//check user count
	if (molch_user_count() != 0) {
		fprintf(stderr, "ERROR: Wrong user count.\n");
		return EXIT_FAILURE;
	}

	int status;
	//create a new user
	buffer_t *alice_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_head_on_keyboard = buffer_create_from_string("mn ujkhuzn7b7bzh6ujg7j8hn");
	status = molch_create_user(
			alice_public_identity->content,
			alice_public_prekeys->content,
			alice_head_on_keyboard->content,
			alice_head_on_keyboard->content_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create Alice! (%i)\n", status);
		molch_destroy_all_users();
		return status;
	}
	printf("Alice public identity (%zi Bytes):\n", alice_public_identity->content_length);
	print_hex(alice_public_identity);
	putchar('\n');

	//check user count
	if (molch_user_count() != 1) {
		fprintf(stderr, "ERROR: Wrong user count.\n");
		molch_destroy_all_users();
		return EXIT_FAILURE;
	}

	//create another user
	buffer_t *bob_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_head_on_keyboard = buffer_create_from_string("jnu8h77z6ht56ftgnujh");
	status = molch_create_user(
			bob_public_identity->content,
			bob_public_prekeys->content,
			bob_head_on_keyboard->content,
			bob_head_on_keyboard->content_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create Bob! (%i)\n", status);
		molch_destroy_all_users();
		return status;
	}
	printf("Bob public identity (%zi Bytes):\n", bob_public_identity->content_length);
	print_hex(bob_public_identity);
	putchar('\n');

	//check user count
	if (molch_user_count() != 2) {
		fprintf(stderr, "ERROR: Wrong user count.\n");
		molch_destroy_all_users();
		return EXIT_FAILURE;
	}

	//check user list
	size_t user_count;
	unsigned char *user_list = molch_user_list(&user_count);
	if ((user_count != 2)
			|| (sodium_memcmp(alice_public_identity->content, user_list, alice_public_identity->content_length) != 0)
			|| (sodium_memcmp(bob_public_identity->content, user_list + crypto_box_PUBLICKEYBYTES, alice_public_identity->content_length) != 0)) {
		fprintf(stderr, "ERROR: Wrong user list.\n");
		free(user_list);
		molch_destroy_all_users();
		return EXIT_FAILURE;
	}
	free(user_list);

	//create a new send conversation (alice sends to bob)
	buffer_t *alice_send_message = buffer_create_from_string("Hi Bob. Alice here!");
	unsigned char *alice_send_packet;
	size_t alice_send_packet_length;
	molch_conversation alice_conversation = molch_create_send_conversation(
			&alice_send_packet,
			&alice_send_packet_length,
			alice_send_message->content,
			alice_send_message->content_length,
			bob_public_prekeys->content,
			alice_public_identity->content,
			bob_public_identity->content);
	if (!alice_conversation.valid) {
		fprintf(stderr, "ERROR: Failed to start send conversation.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		free(alice_send_packet);
		return EXIT_FAILURE;
	}

	//check the message type
	if (molch_get_message_type(alice_send_packet, alice_send_packet_length) != PREKEY_MESSAGE) {
		fprintf(stderr, "ERROR: Wrong message type.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		free(alice_send_packet);
		return EXIT_FAILURE;
	}

	//create a new receive conversation (bob receives from alice)
	unsigned char *bob_receive_message;
	size_t bob_receive_message_length;
	molch_conversation bob_conversation = molch_create_receive_conversation(
			&bob_receive_message,
			&bob_receive_message_length,
			alice_send_packet,
			alice_send_packet_length,
			bob_public_prekeys->content,
			alice_public_identity->content,
			bob_public_identity->content);
	free(alice_send_packet);
	if (!bob_conversation.valid) {
		fprintf(stderr, "ERROR: Failed to start receive conversation.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(bob_receive_message);
		return EXIT_FAILURE;
	}

	//compare sent and received messages
	printf("sent (Alice): %s\n", alice_send_message->content);
	printf("received (Bob): %s\n", bob_receive_message);
	if ((alice_send_message->content_length != bob_receive_message_length)
			|| (sodium_memcmp(alice_send_message->content, bob_receive_message, bob_receive_message_length) != 0)) {
		fprintf(stderr, "ERROR: Incorrect message received.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(bob_receive_message);
		return EXIT_FAILURE;
	}
	free(bob_receive_message);

	//bob replies
	buffer_t *bob_send_message = buffer_create_from_string("Welcome Alice!");
	unsigned char *bob_send_packet;
	size_t bob_send_packet_length;
	status = molch_encrypt_message(
			&bob_send_packet,
			&bob_send_packet_length,
			bob_send_message->content,
			bob_send_message->content_length,
			bob_conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Couldn't send bobs message.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(bob_send_packet);
		return EXIT_FAILURE;
	}

	//check the message type
	if (molch_get_message_type(bob_send_packet, bob_send_packet_length) != NORMAL_MESSAGE) {
		fprintf(stderr, "ERROR: Wrong message type.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(bob_send_packet);
		return EXIT_FAILURE;
	}

	//alice receives reply
	unsigned char *alice_receive_message;
	size_t alice_receive_message_length;
	status = molch_decrypt_message(
			&alice_receive_message,
			&alice_receive_message_length,
			bob_send_packet,
			bob_send_packet_length,
			alice_conversation);
	free(bob_send_packet);
	if (status != 0) {
		fprintf(stderr, "ERROR: Incorrect message received.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(alice_receive_message);
		return EXIT_FAILURE;
	}

	//compare sent and received messages
	printf("sent (Bob): %s\n", bob_send_message->content);
	printf("received (Alice): %s\n", alice_receive_message);
	if ((bob_send_message->content_length != alice_receive_message_length)
			|| (sodium_memcmp(bob_send_message->content, alice_receive_message, alice_receive_message_length) != 0)) {
		fprintf(stderr, "ERROR: Incorrect message received.\n");
		molch_destroy_all_users();
		molch_destroy_conversation(alice_conversation);
		molch_destroy_conversation(bob_conversation);
		free(alice_receive_message);
		return EXIT_FAILURE;
	}
	free(alice_receive_message);

	//destroy the conversations
	molch_destroy_conversation(alice_conversation);
	molch_destroy_conversation(bob_conversation);

	//destroy the users again
	molch_destroy_all_users();

	//check user count
	if (molch_user_count() != 0) {
		fprintf(stderr, "ERROR: Wrong user count.\n");
		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}
