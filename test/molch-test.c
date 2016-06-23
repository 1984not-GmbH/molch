/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	//mustn't crash here!
	molch_destroy_all_users();

	int status_int = 0;
	return_status status = return_status_init();

	//backup key buffer
	buffer_t *backup_key = buffer_create_on_heap(BACKUP_KEY_SIZE, BACKUP_KEY_SIZE);

	//create conversation buffers
	buffer_t *alice_conversation = buffer_create_on_heap(CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	buffer_t *bob_conversation = buffer_create_on_heap(CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);

	//message numbers
	uint32_t alice_receive_message_number = UINT32_MAX;
	uint32_t alice_previous_receive_message_number = UINT32_MAX;

	//alice key buffers
	buffer_t *alice_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	unsigned char *alice_public_prekeys = NULL;
	size_t alice_public_prekeys_length = 0;

	//bobs key buffers
	buffer_t *bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	unsigned char *bob_public_prekeys = NULL;
	size_t bob_public_prekeys_length = 0;

	//packet pointers
	unsigned char * alice_send_packet = NULL;
	unsigned char * bob_send_packet = NULL;

	unsigned char *printed_status = NULL;

	// JSON for empty library
	buffer_create_from_string(empty_array, "[]");
	size_t empty_json_length;
	unsigned char *empty_json = NULL;
	status = molch_json_export(&empty_json, &empty_json_length);
	throw_on_error(EXPORT_ERROR, "Failed to export to JSON.");
	printf("%.*s\n", (int)empty_json_length, (char*)empty_json);
	if (buffer_compare_to_raw(empty_array, empty_json, empty_json_length) != 0) {
		throw(INCORRECT_DATA, "Incorrect JSON output when there is no user.");
	}

	//check user count
	if (molch_user_count() != 0) {
		throw(INVALID_VALUE, "Wrong user count.");
	}


	//create a new user
	buffer_create_from_string(alice_head_on_keyboard, "mn ujkhuzn7b7bzh6ujg7j8hn");
	unsigned char *complete_json_export = NULL;
	size_t complete_json_export_length = 0;
	status = molch_create_user(
			alice_public_identity->content,
			&alice_public_prekeys,
			&alice_public_prekeys_length,
			alice_head_on_keyboard->content,
			alice_head_on_keyboard->content_length,
			&complete_json_export,
			&complete_json_export_length);
	throw_on_error(status.status, "Failed to create Alice!");

	printf("Alice public identity (%zu Bytes):\n", alice_public_identity->content_length);
	print_hex(alice_public_identity);
	putchar('\n');
	if (complete_json_export == NULL) {
		throw(EXPORT_ERROR, "Failed to export the librarys state as JSON after creating alice.");
	}
	printf("%.*s\n", (int)complete_json_export_length, (char*)complete_json_export);
	sodium_free(complete_json_export);


	//check user count
	if (molch_user_count() != 1) {
		throw(INVALID_VALUE, "Wrong user count.");
	}

	//create a new backup key
	status = molch_update_backup_key(backup_key->content);
	throw_on_error(KEYGENERATION_FAILED, "Failed to update the backup key.");

	printf("Updated backup key:\n");
	print_hex(backup_key);
	putchar('\n');

	//create another user
	buffer_create_from_string(bob_head_on_keyboard, "jnu8h77z6ht56ftgnujh");
	status = molch_create_user(
			bob_public_identity->content,
			&bob_public_prekeys,
			&bob_public_prekeys_length,
			bob_head_on_keyboard->content,
			bob_head_on_keyboard->content_length,
			NULL,
			NULL);
	throw_on_error(status.status, "Failed to create Bob!");

	printf("Bob public identity (%zu Bytes):\n", bob_public_identity->content_length);
	print_hex(bob_public_identity);
	putchar('\n');

	//check user count
	if (molch_user_count() != 2) {
		throw(INVALID_VALUE, "Wrong user count.");
	}

	//check user list
	size_t user_count;
	unsigned char *user_list = NULL;
	status = molch_user_list(&user_list, &user_count);
	throw_on_error(CREATION_ERROR, "Failed to list users.");
	if ((user_count != 2)
			|| (sodium_memcmp(alice_public_identity->content, user_list, alice_public_identity->content_length) != 0)
			|| (sodium_memcmp(bob_public_identity->content, user_list + crypto_box_PUBLICKEYBYTES, alice_public_identity->content_length) != 0)) {
		free(user_list);
		throw(INCORRECT_DATA, "User list is incorrect.");
	}
	free(user_list);

	//create a new send conversation (alice sends to bob)
	buffer_create_from_string(alice_send_message, "Hi Bob. Alice here!");
	size_t alice_send_packet_length;
	status = molch_create_send_conversation(
			alice_conversation->content,
			&alice_send_packet,
			&alice_send_packet_length,
			alice_send_message->content,
			alice_send_message->content_length,
			bob_public_prekeys,
			bob_public_prekeys_length,
			alice_public_identity->content,
			bob_public_identity->content,
			NULL,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to start send conversation.");

	//check conversation export
	size_t number_of_conversations;
	unsigned char *conversation_list = NULL;
	status = molch_list_conversations(alice_public_identity->content, &conversation_list, &number_of_conversations);
	throw_on_error(GENERIC_ERROR, "Failed to list conversations.");
	if ((number_of_conversations != 1) || (buffer_compare_to_raw(alice_conversation, conversation_list, alice_conversation->content_length) != 0)) {
		free(conversation_list);
		throw(GENERIC_ERROR, "Failed to list conversations.");
	}
	free(conversation_list);

	//check the message type
	if (molch_get_message_type(alice_send_packet, alice_send_packet_length) != PREKEY_MESSAGE) {
		throw(INVALID_VALUE, "Wrong message type.");
	}

	if (bob_public_prekeys != NULL) {
		free(bob_public_prekeys);
		bob_public_prekeys = NULL;
	}

	// delete
	free(alice_public_prekeys);
	alice_public_prekeys = NULL;

	// export the prekeys again
	status = molch_get_prekey_list(
			alice_public_identity->content,
			&alice_public_prekeys,
			&alice_public_prekeys_length);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get Alice' prekey list.");

	//create a new receive conversation (bob receives from alice)
	unsigned char *bob_receive_message;
	size_t bob_receive_message_length;
	status = molch_create_receive_conversation(
			bob_conversation->content,
			&bob_receive_message,
			&bob_receive_message_length,
			alice_send_packet,
			alice_send_packet_length,
			&bob_public_prekeys,
			&bob_public_prekeys_length,
			alice_public_identity->content,
			bob_public_identity->content,
			NULL,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to start receive conversation.");

	//compare sent and received messages
	printf("sent (Alice): %s\n", alice_send_message->content);
	printf("received (Bob): %s\n", bob_receive_message);
	if ((alice_send_message->content_length != bob_receive_message_length)
			|| (sodium_memcmp(alice_send_message->content, bob_receive_message, bob_receive_message_length) != 0)) {
		free(bob_receive_message);
		throw(GENERIC_ERROR, "Incorrect message received.");
	}
	free(bob_receive_message);

	//bob replies
	buffer_create_from_string(bob_send_message, "Welcome Alice!");
	size_t bob_send_packet_length;
	unsigned char * conversation_json_export = NULL;
	size_t conversation_json_export_length = 0;
	status = molch_encrypt_message(
			&bob_send_packet,
			&bob_send_packet_length,
			bob_send_message->content,
			bob_send_message->content_length,
			bob_conversation->content,
			&conversation_json_export,
			&conversation_json_export_length);
	throw_on_error(GENERIC_ERROR, "Couldn't send bobs message.");

	if (conversation_json_export == NULL) {
		throw(EXPORT_ERROR, "Failed to export the conversation after encrypting a message.");
	}
	printf("%.*s\n", (int)conversation_json_export_length, (char*)conversation_json_export);
	sodium_free(conversation_json_export);

	//check the message type
	if (molch_get_message_type(bob_send_packet, bob_send_packet_length) != NORMAL_MESSAGE) {
		throw(INVALID_VALUE, "Wrong message type.");
	}

	//alice receives reply
	unsigned char *alice_receive_message;
	size_t alice_receive_message_length;
	status = molch_decrypt_message(
			&alice_receive_message,
			&alice_receive_message_length,
			bob_send_packet,
			bob_send_packet_length,
			alice_conversation->content,
			&alice_receive_message_number,
			&alice_previous_receive_message_number,
			NULL,
			NULL);
	on_error(
		free(alice_receive_message);
		throw(GENERIC_ERROR, "Incorrect message received.");
	)

	if ((alice_receive_message_number != 0) || (alice_previous_receive_message_number != 0)) {
		free(alice_receive_message);
		throw(INCORRECT_DATA, "Incorrect receive message number for Alice.");
	}

	//compare sent and received messages
	printf("sent (Bob): %s\n", bob_send_message->content);
	printf("received (Alice): %s\n", alice_receive_message);
	if ((bob_send_message->content_length != alice_receive_message_length)
			|| (sodium_memcmp(bob_send_message->content, alice_receive_message, alice_receive_message_length) != 0)) {
		free(alice_receive_message);
		throw(GENERIC_ERROR, "Incorrect message received.");
	}
	free(alice_receive_message);

	//test JSON export
	printf("Test JSON export:\n");
	size_t json_length;
	unsigned char *json = NULL;
	status = molch_json_export(&json, &json_length);
	throw_on_error(EXPORT_ERROR, "Failed to export to JSON.");

	printf("%.*s\n", (int)json_length, json);

	//test JSON import
	printf("Test JSON import:\n");
	status = molch_json_import(json, json_length);
	on_error(
		sodium_free(json);
		throw(IMPORT_ERROR, "Failed to import JSON.");
	)

	//now export again
	size_t imported_json_length;
	unsigned char *imported_json = NULL;
	status = molch_json_export(&imported_json, &imported_json_length);
	on_error(
		sodium_free(json);
		throw(EXPORT_ERROR, "Failed to export imported JSON.");
	)

	//compare
	if ((json_length != imported_json_length) || (sodium_memcmp(json, imported_json, json_length) != 0)) {
		sodium_free(json);
		sodium_free(imported_json);
		throw(IMPORT_ERROR, "Imported JSON is incorrect.");
	}
	sodium_free(json);
	sodium_free(imported_json);

	//test conversation JSON export
	status = molch_conversation_json_export(&json, alice_conversation->content, &json_length);
	throw_on_error(EXPORT_ERROR, "Failed to export Alice' conversation as JSON.");

	printf("Alice' conversation exported to JSON:\n");
	printf("%.*s\n", (int)json_length, (char*)json);

	//import again
	status = molch_conversation_json_import(json, json_length);
	on_error(
		sodium_free(json);
		throw(IMPORT_ERROR, "Failed to import Alice' conversation from JSON.");
	)

	//export again
	status = molch_conversation_json_export(&imported_json, alice_conversation->content, &imported_json_length);
	on_error(
		sodium_free(json);
		throw(EXPORT_ERROR, "Failed to export Alice imported conversation as JSON.");
	)

	//compare
	if ((json_length != imported_json_length) || (sodium_memcmp(json, imported_json, json_length) != 0)) {
		sodium_free(json);
		sodium_free(imported_json);
		throw(IMPORT_ERROR, "JSON of imported conversation is incorrect.");
	}

	sodium_free(imported_json);
	sodium_free(json);

	//destroy the conversations
	molch_end_conversation(alice_conversation->content, NULL, NULL);
	molch_end_conversation(bob_conversation->content, NULL, NULL);

	//destroy the users again
	molch_destroy_all_users();

	//check user count
	if (molch_user_count() != 0) {
		throw(INVALID_VALUE, "Wrong user count.");
	}

	//TODO check detection of invalid prekey list signatures and old timestamps + more scenarios

	buffer_create_from_string(success_buffer, "SUCCESS");
	size_t printed_status_length = 0;
	printed_status = (unsigned char*) molch_print_status(return_status_init(), &printed_status_length);
	if (buffer_compare_to_raw(success_buffer, printed_status, printed_status_length) != 0) {
		throw(INCORRECT_DATA, "molch_print_status produces incorrect output.");
	}

cleanup:
	if (alice_public_prekeys != NULL) {
		free(alice_public_prekeys);
	}
	if (bob_public_prekeys != NULL) {
		free(bob_public_prekeys);
	}
	if (alice_send_packet != NULL) {
		free(alice_send_packet);
	}
	if (bob_send_packet != NULL) {
		free(bob_send_packet);
	}
	if (printed_status != NULL) {
		free(printed_status);
	}
	molch_destroy_all_users();
	buffer_destroy_from_heap(alice_conversation);
	buffer_destroy_from_heap(bob_conversation);
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(backup_key);

	if (status.status != SUCCESS) {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	if (status_int != 0) {
		status.status = GENERIC_ERROR;
	}

	return status.status;
}
