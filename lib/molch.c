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

/*
 * WARNING: ALTHOUGH THIS IMPLEMENTS THE AXOLOTL PROTOCOL, IT ISN't CONSIDERED SECURE ENOUGH TO USE AT THIS POINT
 */

#include <string.h>
#include <assert.h>
#include <alloca.h>
#include <stdint.h>

#include "constants.h"
#include "molch.h"
#include "packet.h"
#include "../buffer/buffer.h"
#include "user-store.h"
#include "spiced-random.h"
#include "endianness.h"

//global user store
static user_store *users = NULL;

/*
 * Create a prekey list.
 */
int create_prekey_list(
		const buffer_t * const public_signing_key,
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length) {

	int status = 0;

	//create buffers
	buffer_t *unsigned_prekey_list = buffer_create_on_heap(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t),
			0);
	buffer_t *prekey_list_buffer = buffer_create_on_heap(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t) + SIGNATURE_SIZE,
			0);
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//buffer for the prekey part of unsigned_prekey_list
	buffer_create_with_existing_array(prekeys, unsigned_prekey_list->content + PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);


	//get the user
	user_store_node *user = user_store_find_node(users, public_signing_key);
	if (user == NULL) {
		status = -1;
		goto cleanup;
	}

	//get the public identity key
	status = master_keys_get_identity_key(
			user->master_keys,
			public_identity_key);
	if (status != 0) {
		goto cleanup;
	}

	//copy the public identity to the prekey list
	status = buffer_copy(unsigned_prekey_list, 0, public_identity_key, 0, PUBLIC_KEY_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	//get the prekey list
	status = prekey_store_list(user->prekeys, prekeys);
	if (status != 0) {
		goto cleanup;
	}

	//add the timestamp
	time_t timestamp = time(NULL);
	buffer_create_with_existing_array(big_endian_timestamp, unsigned_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_to_big_endian(timestamp, big_endian_timestamp);
	if (status != 0) {
		goto cleanup;
	}
	unsigned_prekey_list->content_length = unsigned_prekey_list->buffer_length;

	//sign the prekey list with the current identity key
	status = master_keys_sign(
			user->master_keys,
			unsigned_prekey_list,
			prekey_list_buffer);
	if (status != 0) {
		goto cleanup;
	}

	*prekey_list = prekey_list_buffer->content;
	*prekey_list_length = prekey_list_buffer->content_length;

cleanup:
	if (status != 0) {
		free(prekey_list_buffer->content);
	}

	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(unsigned_prekey_list);
	free(prekey_list_buffer);

	return status;
}

/*
 * Create a new user. The user is identified by the public key.
 *
 * Get's random input (can be in any format and doesn't have
 * to be uniformly distributed) and uses it in combination
 * with the OS's random number generator to generate a
 * identity keypair for the user.
 *
 * IMPORTANT: Don't put random numbers provided by the operating
 * system in there.
 *
 * This also creates a signed list of prekeys to be uploaded to
 * the server.
 *
 * Returns 0 on success.
 */
int molch_create_user(
		unsigned char * const public_master_key, //output, PUBLIC_MASTER_KEY_SIZE
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length,
		const unsigned char * const random_data,
		const size_t random_data_length) {
	//create user store if it doesn't exist already
	if (users == NULL) {
		if (sodium_init() == -1) {
			return -1;
		}
		users = user_store_create();
		if (users == NULL) { //failed to create user store
			return -10;
		}
	}

	//create buffers wrapping the raw arrays
	buffer_create_with_existing_array(random_data_buffer, (unsigned char*)random_data, random_data_length);
	buffer_create_with_existing_array(public_master_key_buffer, public_master_key, PUBLIC_MASTER_KEY_SIZE);

	int status = 0;

	//create the user
	status = user_store_create_user(
			users,
			random_data_buffer,
			public_master_key_buffer,
			NULL);
	if (status != 0) {
		goto cleanup;
	}

	status = create_prekey_list(
			public_master_key_buffer,
			prekey_list,
			prekey_list_length);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		molch_destroy_user(public_master_key);
	}

	return status;
}

/*
 * Destroy a user.
 */
//(although they are selfcontained, so maybe not)
int molch_destroy_user(const unsigned char * const public_signing_key) {
	if (users == NULL) {
		return -1;
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	buffer_create_with_existing_array(public_signing_key_buffer, (unsigned char*)public_signing_key, PUBLIC_KEY_SIZE);
	user_store_remove_by_key(users, public_signing_key_buffer);

	return 0;
}

/*
 * Get the number of users.
 */
size_t molch_user_count() {
	if (users == NULL) {
		return 0;
	}

	return users->length;
}

/*
 * Delete all users.
 */
void molch_destroy_all_users() {
	if (users != NULL) {
		user_store_clear(users);
	}

	users = NULL;
}

/*
 * List all of the users (list of the public keys),
 * NULL if there are no users.
 */
unsigned char *molch_user_list(size_t *count) {
	if (users == NULL) {
		return NULL;
	}

	//get the list of users and copy it
	buffer_t *user_list_buffer = user_store_list(users);
	if (user_list_buffer == NULL) {
		return NULL;
	}

	*count = molch_user_count();

	unsigned char *user_list = user_list_buffer->content;
	free(user_list_buffer); //free the buffer_t struct while leaving content intact

	return user_list;
}

/*
 * Get the type of a message.
 *
 * This is either a normal message or a prekey message.
 * Prekey messages mark the start of a new conversation.
 */
molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length) {

	//create a buffer for the packet
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);

	unsigned char packet_type;
	unsigned char current_protocol_version;
	unsigned char highest_supported_protocol_version;
	unsigned char header_length;
	int status = packet_get_metadata_without_verification(
		packet_buffer,
		&packet_type,
		&current_protocol_version,
		&highest_supported_protocol_version,
		&header_length,
		NULL,
		NULL,
		NULL);
	if (status != 0) {
		return INVALID;
	}

	if (packet_type == PREKEY_MESSAGE) {
		return PREKEY_MESSAGE;
	}

	if (packet_type == NORMAL_MESSAGE) {
		return NORMAL_MESSAGE;
	}

	return INVALID;
}

/*
 * Verify prekey list and extract the public identity
 * and choose a prekey.
 */
int verify_prekey_list(
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		buffer_t * const public_identity_key, //output, PUBLIC_KEY_SIZE
		const buffer_t * const public_signing_key
		) {

	buffer_t *verified_prekey_list = buffer_create_on_heap(prekey_list_length - SIGNATURE_SIZE, prekey_list_length - SIGNATURE_SIZE);

	int status = 0;

	//verify the signature
	unsigned long long verified_length;
	status = crypto_sign_open(
			verified_prekey_list->content,
			&verified_length,
			prekey_list,
			(unsigned long long)prekey_list_length,
			public_signing_key->content);
	if (status != 0) {
		goto cleanup;
	}
	verified_prekey_list->content_length = verified_length;

	//get the timestamp
	time_t timestamp;
	buffer_create_with_existing_array(big_endian_timestamp, verified_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_from_big_endian(&timestamp, big_endian_timestamp);
	if (status != 0) {
		goto cleanup;
	}

	//make sure the prekey list isn't to old
	time_t current_time = time(NULL);
	if ((timestamp + 3600 * 24 * 31 * 3) < current_time) { //timestamp is older than 3 months
		status = -1;
		goto cleanup;
	}

	//copy the public identity key
	status = buffer_copy(
			public_identity_key,
			0,
			verified_prekey_list,
			0,
			PUBLIC_KEY_SIZE);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(verified_prekey_list);

	return status;
}

/*
 * Start a new conversation. (sending)
 *
 * The conversation can be identified by it's ID
 *
 * This requires a new set of prekeys from the receiver.
 *
 * Returns 0 on success.
 */
int molch_create_send_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const prekey_list, //prekey list of the receiver (PREKEY_AMOUNT * PUBLIC_KEY_SIZE)
		const size_t prekey_list_length,
		const unsigned char * const sender_public_signing_key, //signing key of the sender (user)
		const unsigned char * const receiver_public_signing_key) { //signing key of the receiver

	//check input
	if ((conversation_id == NULL)
			|| (packet == NULL)
			|| (packet_length == NULL)
			|| (prekey_list == NULL)
			|| (sender_public_signing_key == NULL)
			|| (receiver_public_signing_key == NULL)) {
		return -1;
	}

	//create buffers wrapping the raw input
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(message_buffer, (unsigned char*)message, message_length);
	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*)sender_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(prekeys, (unsigned char*)prekey_list + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t));

	//get the user that matches the public signing key of the sender
	user_store_node *user = user_store_find_node(users, sender_public_signing_key_buffer);
	if (user == NULL) {
		return -1;
	}

	//create buffers
	buffer_t *sender_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	conversation_t *conversation = NULL;
	buffer_t *packet_buffer = NULL;

	int status = 0;

	//get the receivers public ephemeral and identity
	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_identity,
			receiver_public_signing_key_buffer);
	if (status != 0) {
		goto cleanup;
	}

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	//create the conversation and encrypt the message
	conversation = conversation_start_send_conversation(
			message_buffer,
			&packet_buffer,
			user->master_keys->public_identity_key,
			user->master_keys->private_identity_key,
			receiver_public_identity,
			prekeys);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	//copy the conversation id
	status = buffer_clone(conversation_id_buffer, conversation->id);
	if (status != 0) {
		goto cleanup;
	}

	status = conversation_store_add(user->conversations, conversation);
	if (status != 0) {
		goto cleanup;
	}
	conversation = NULL;

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

cleanup:
	buffer_destroy_from_heap(sender_public_identity);
	buffer_destroy_from_heap(receiver_public_identity);
	buffer_destroy_from_heap(receiver_public_ephemeral);

	if (conversation != NULL) {
		conversation_destroy(conversation);
	}

	if (user != NULL) {
		sodium_mprotect_noaccess(user->master_keys);
	}

	if (status != 0) {
		if (packet_buffer != NULL) {
			free(packet_buffer->content);
		}
	}

	if (packet_buffer != NULL) {
		free(packet_buffer);
	}

	return status;
}

/*
 * Start a new conversation. (receiving)
 *
 * This also generates a new set of prekeys to be uploaded to the server.
 *
 * This function is called after receiving a prekey message.
 *
 * conversation->valid is false on failure
 */
int molch_create_receive_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		unsigned char ** const prekey_list, //output, free after use
		size_t * const prekey_list_length,
		const unsigned char * const sender_public_signing_key, //signing key of the sender
		const unsigned char * const receiver_public_signing_key) { //signing key of the receiver (user)

	//create buffers to wrap the raw arrays
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);
	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*) sender_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_MASTER_KEY_SIZE);

	//get the user that matches the public signing key of the receiver
	user_store_node *user = user_store_find_node(users, receiver_public_signing_key_buffer);
	if (user == NULL) {
		return -1;
	}

	conversation_t *conversation = NULL;
	buffer_t *message_buffer = NULL;

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	int status = 0;

	//create the conversation
	conversation = conversation_start_receive_conversation(
			packet_buffer,
			&message_buffer,
			user->master_keys->public_identity_key,
			user->master_keys->private_identity_key,
			user->prekeys);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	//copy the conversation id
	status = buffer_clone(conversation_id_buffer, conversation->id);
	if (status != 0) {
		goto cleanup;
	}

	//create the prekey list
	status = create_prekey_list(
			receiver_public_signing_key_buffer,
			prekey_list,
			prekey_list_length);
	if (status != 0) {
		goto cleanup;
	}

	//add the conversation to the conversation store
	status = conversation_store_add(user->conversations, conversation);
	if (status != 0) {
		goto cleanup;
	}
	conversation = NULL;

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;


cleanup:
	if (status != 0) {
		if (message_buffer != NULL) {
			free(message_buffer->content);
		}
	}

	if (message_buffer != NULL) {
		free(message_buffer);
	}

	if (conversation != NULL) {
		conversation_destroy(conversation);
	}

	if (user != NULL) {
		sodium_mprotect_noaccess(user->master_keys);
	}

	return status;
}

/*
 * Find a conversation based on it's conversation id.
 */
conversation_t *find_conversation(const unsigned char * const conversation_id) {
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);

	//go through all the users
	user_store_node *node = users->head;
	conversation_t *conversation_node = NULL;
	while (node != NULL) {
		conversation_node = conversation_store_find_node(node->conversations, conversation_id_buffer);
		if (conversation_node != NULL) {
			//found the conversation where searching for
			break;
		}
		user_store_node *next = node->next;
		node = next;
	}

	if (conversation_node == NULL) {
		return NULL;
	}

	return conversation_node;
}

/*
 * Encrypt a message and create a packet that can be sent to the receiver.
 *
 * Returns 0 on success.
 */
int molch_encrypt_message(
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output, length of the packet
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id) {

	//create buffer for message array
	buffer_create_with_existing_array(message_buffer, (unsigned char*) message, message_length);

	int status = 0;

	buffer_t *packet_buffer = NULL;

	//find the conversation
	conversation_t *conversation = find_conversation(conversation_id);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	status = conversation_send(
			conversation,
			message_buffer,
			&packet_buffer,
			NULL,
			NULL,
			NULL);
	if (status != 0) {
		goto cleanup;
	}

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

cleanup:
	if (status != 0) {
		if (packet_buffer != NULL) {
			free(packet_buffer->content);
		}
	}

	if (packet_buffer != NULL) {
		free(packet_buffer);
	}

	return status;
}

/*
 * Decrypt a message.
 *
 * Returns 0 on success.
 */
int molch_decrypt_message(
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t *message_length, //output
		const unsigned char * const packet, //received packet
		const size_t packet_length,
		const unsigned char * const conversation_id) {

	//create buffer for the packet
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);

	int status;

	buffer_t *message_buffer = NULL;

	//find the conversation
	conversation_t *conversation = find_conversation(conversation_id);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	status = conversation_receive(
			conversation,
			packet_buffer,
			&message_buffer);
	if (status != 0) {
		goto cleanup;
	}

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;

cleanup:
	if (status != 0) {
		if (message_buffer != NULL) {
			free(message_buffer->content);
		}
	}

	if (message_buffer != NULL) {
		free(message_buffer);
	}
	return status;
}

/*
 * Destroy a conversation.
 *
 * This will almost certainly be changed later on!!!!!!
 */
void molch_end_conversation(const unsigned char * const conversation_id) {
	//find the conversation
	conversation_t *conversation = find_conversation(conversation_id);
	if (conversation == NULL) {
		return;
	}
	//find the corresponding user
	user_store_node *user = user_store_find_node(users, conversation->ratchet->our_public_identity);
	if (user == NULL) {
		return;
	}
	conversation_store_remove_by_id(user->conversations, conversation->id);
}

/*
 * List the conversations of a user.
 *
 * Returns the number of conversations and a list of conversations for a given user.
 * (all the conversation ids in one big list).
 *
 * Don't forget to free it after use.
 *
 * number is set to the number of conversations or SIZE_MAX if there is any error
 * (e.g. the user doesn't exist)
 *
 * Returns NULL if the user doesn't exist or if there is no conversation.
 */
unsigned char *molch_list_conversations(const unsigned char * const user_public_identity, size_t *number) {
	buffer_create_with_existing_array(user_public_identity_buffer, (unsigned char*)user_public_identity, PUBLIC_KEY_SIZE);
	user_store_node *user = user_store_find_node(users, user_public_identity_buffer);
	if (user == NULL) {
		*number = SIZE_MAX;
		return NULL;
	}

	buffer_t *conversation_id_buffer = conversation_store_list(user->conversations);

	if (conversation_id_buffer == NULL) {
		*number = 0;
		return NULL;
	}

	if ((conversation_id_buffer->content_length % CONVERSATION_ID_SIZE) != 0) {
		*number = SIZE_MAX;
		buffer_destroy_from_heap(conversation_id_buffer);
		return NULL;
	}
	*number = conversation_id_buffer->content_length / CONVERSATION_ID_SIZE;

	unsigned char *conversation_ids = conversation_id_buffer->content;
	free(conversation_id_buffer); //free buffer_t struct

	return conversation_ids;
}

/*
 * Serialize a conversation into JSON.
 *
 * Use sodium_free to free it after use.
 *
 * Returns NULL on failure.
 */
unsigned char *molch_conversation_json_export(const unsigned char * const conversation_id, size_t * const length) {
	//check input
	if ((conversation_id == NULL) || (length == NULL)) {
		return NULL;
	}

	conversation_t *conversation = find_conversation(conversation_id);
	if (conversation == NULL) {
		return NULL;
	}

	mcJSON *json = NULL;
	unsigned char *json_string_content = NULL;
	mempool_t *json_string = NULL;
	int status = 0;

	//allocate a memory pool
	//FIXME: Don't allocate a fixed amount
	mempool_t *pool = buffer_create_with_custom_allocator(1000000, 0, sodium_malloc, sodium_free);
	if (pool == NULL) {
		status = -1;
		goto cleanup;
	}

	json = conversation_json_export(conversation, pool);
	if (json == NULL) {
		status = -1;
		goto cleanup;
	}

	//print to string
	//FIXME: Don't allocate a fixed amount
	json_string = mcJSON_PrintBuffered(json, 100000, false);
	if (json_string == NULL) {
		status = -1;
		goto cleanup;
	}

	*length = json_string->content_length;
	json_string_content = json_string->content;

cleanup:
	buffer_destroy_with_custom_deallocator(pool, sodium_free);

	if (status != 0) {
		if (json != NULL) {
			free(json);
		}

		if (json_string != NULL) {
			buffer_destroy_with_custom_deallocator(json_string, sodium_free);
		}

		return NULL;
	}

	sodium_free(json_string);

	return json_string_content;
}

/*
 * Serialise molch's state into JSON.
 *
 * Use sodium_free to free it after use!
 *
 * Returns NULL on failure.
 */
unsigned char *molch_json_export(size_t *length) {
	//set allocation functions of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	//allocate a memory pool
	//FIXME: Don't allocate a fixed amount
	unsigned char *pool_content = sodium_malloc(5000000);
	mempool_t *pool = alloca(sizeof(mempool_t));
	buffer_init_with_pointer(
			pool,
			pool_content,
			5000000,
			0);

	//serialize state into tree of mcJSON objects
	mcJSON *json = user_store_json_export(users, pool);
	if (json == NULL) {
		sodium_free(pool_content);
		*length = 0;
		return NULL;
	}

	//print to string
	//FIXME: Don't allocate a fixed amount (that's the only way to do it right now unfortunately)
	buffer_t *printed_json = mcJSON_PrintBuffered(json, 5000000, false);
	sodium_free(pool_content);
	if (printed_json == NULL) {
		*length = 0;
		return NULL;
	}

	*length = printed_json->content_length;
	unsigned char *printed_json_content = printed_json->content;
	sodium_free(printed_json); //free the buffer_t struct (leaving content intact)

	return printed_json_content;
}

/*
 * Import the molch's state from JSON (overwrites the current state!)
 *
 * Returns 0 on success.
 */
int molch_json_import(const unsigned char *const json, const size_t length){
	//set allocation functions of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	//create buffer for the json string
	buffer_create_with_existing_array(json_buffer, (unsigned char*)json, length);

	//parse the json
	//FIXME: Don't allocate fixed amount
	mcJSON *json_tree = mcJSON_ParseBuffered(json_buffer, 5000000);
	if (json_tree == NULL) {
		return -1;
	}

	//backup the old user_store
	user_store *users_backup = users;

	//import the user store from json
	users = user_store_json_import(json_tree);
	if (users == NULL) {
		users = users_backup; //roll back backup
		return -2;
	}

	user_store_destroy(users_backup);

	return 0;
}
