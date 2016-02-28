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
 * WARNING: THIS IS ONLY A DUMMY IMPLEMENTATION OF THE HEADER WITHOUT USING ANY ENCRYPTION.
 */

#include <string.h>
#include <assert.h>
#include <alloca.h>
#include <stdint.h>

#include "constants.h"
#include "molch.h"
#include "../buffer/buffer.h"
#include "user-store.h"
#include "spiced-random.h"

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
			PUBLIC_MASTER_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(time_t),
			0); //FIXME this is currently architecture dependent because of time_t
	buffer_t *prekey_list_buffer = buffer_create_on_heap(
			PUBLIC_MASTER_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(time_t) + SIGNATURE_SIZE,
			0); //FIXME this is currently architecture dependent because of time_t
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//buffer for the prekey part of unsigned_prekey_list
	buffer_t prekeys[1];
	buffer_init_with_pointer(prekeys, unsigned_prekey_list->content + PUBLIC_MASTER_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);


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

	//add the timestamp FIXME: This is currently architecture dependent
	//because of Endianness and size of time_t
	time_t timestamp = time(NULL);
	status = buffer_copy_from_raw(
			unsigned_prekey_list,
			PUBLIC_MASTER_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE,
			(unsigned char*) &timestamp,
			0,
			sizeof(time_t));
	if (status != 0) {
		goto cleanup;
	}

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
 * with the OS's random number generator to generate an
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
	buffer_t random_data_buffer[1];
	buffer_init_with_pointer(random_data_buffer, (unsigned char*)random_data, random_data_length, random_data_length);
	buffer_t public_master_key_buffer[1];
	buffer_init_with_pointer(public_master_key_buffer, public_master_key, PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);

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
	if (packet_length < sizeof(molch_message_type)) {
		return INVALID;
	}

	//beginning of the packet is the packet type (molch_message_type enum)
	switch (*((molch_message_type*) packet)) {
		case PREKEY_MESSAGE:
			return PREKEY_MESSAGE;
		case NORMAL_MESSAGE:
			return NORMAL_MESSAGE;
		default:
			return INVALID;
	}
}

/*
 * Create a conversation (for now, for refactoring) FIXME: Remove this.
 */
conversation_t *create_conversation(
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {
	conversation_t *conversation = malloc(sizeof(conversation_t));
	if (conversation == NULL) {
		return NULL;
	}

	buffer_init_with_pointer(conversation->id, conversation->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	conversation->ratchet = NULL;
	conversation->previous = NULL;
	conversation->next = NULL;

	int status = 0;

	//create random id
	if (buffer_fill_random(conversation->id, CONVERSATION_ID_SIZE) != 0) {
		status = -1;
		goto cleanup;
	}

	conversation->ratchet = ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if (conversation->ratchet == NULL) {
		status = -2;
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		free(conversation);

		return NULL;
	}

	return conversation;
}

/*
 * Verify prekey list and extract the public identity
 * and choose a prekey.
 */
int verify_prekey_list(
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		buffer_t * const prekey, //output, PUBLIC_KEY_SIZE
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
	status = buffer_copy_to_raw(
			(unsigned char*)&timestamp,
			0,
			verified_prekey_list,
			PUBLIC_MASTER_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE,
			sizeof(time_t));
	if (status != 0) {
		goto cleanup;
	}

	//make sure the prekey list isn't to old
	time_t current_time = time(NULL);
	if ((timestamp + 3600 * 24 * 31 * 3) < current_time) { //timestamp is older than 3 months
		status = -1;
		goto cleanup;
	}

	//choose a random prekey
	uint32_t prekey_number = randombytes_uniform(PREKEY_AMOUNT);
	status = buffer_copy(
			prekey,
			0,
			verified_prekey_list,
			PUBLIC_MASTER_KEY_SIZE + prekey_number * PUBLIC_KEY_SIZE,
			PUBLIC_KEY_SIZE);
	if (status != 0) {
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
	if (status != 0) {
		prekey->content_length = 0;
	}

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

	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*)sender_public_signing_key, PUBLIC_KEY_SIZE);
	//get the user that matches the public signing key of the sender
	user_store_node *user = user_store_find_node(users, sender_public_signing_key_buffer);
	if (user == NULL) {
		return -1;
	}

	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_KEY_SIZE);

	//create ephemeral keys
	buffer_t *our_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *our_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	conversation_t *conversation = NULL;

	int status = crypto_box_keypair(our_public_ephemeral->content, our_private_ephemeral->content);
	if (status != 0) {
		status = -2;
		goto cleanup;
	}

	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_ephemeral,
			receiver_public_identity,
			receiver_public_signing_key_buffer);
	if (status != 0) {
		goto cleanup;
	}

	//create a conversation
	conversation = create_conversation(
			user->public_signing_key, //FIXME: this is bullshit, on purpose!
			user->public_signing_key, //FIXME: this is bullshit, on purpose!
			receiver_public_signing_key_buffer,
			our_private_ephemeral,
			our_public_ephemeral,
			receiver_public_ephemeral);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	//start a conversation
	status = conversation_store_add(user->conversations, conversation);
	//copy the conversation id
	if (status == 0) {
		status = buffer_clone_to_raw(conversation_id, CONVERSATION_ID_SIZE, user->conversations->tail->id);
		if (status != 0) {
			conversation_store_remove(user->conversations, user->conversations->tail);
		}
	}
	conversation = NULL;
	if (status != 0) {
		goto cleanup;
	}

	//create the packet
	status = molch_encrypt_message(packet, packet_length, message, message_length, conversation_id);
	if (status != 0) {
		free(*packet);
		*packet_length = 0;
		goto cleanup;
	}

	//make message type PREKEY_MESSAGE
	static const molch_message_type PREKEY = PREKEY_MESSAGE;
	memcpy(*packet, &PREKEY, sizeof(molch_message_type));

cleanup:
	if (conversation != NULL) {
		conversation_destroy(conversation);
	}

	buffer_destroy_from_heap(our_public_ephemeral);
	buffer_destroy_from_heap(our_private_ephemeral);
	buffer_destroy_from_heap(receiver_public_ephemeral);
	buffer_destroy_from_heap(receiver_public_identity);

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
	//check packet size
	if (packet_length < (sizeof(molch_message_type) + PUBLIC_KEY_SIZE)) {
		return -1;
	}

	//check packet type
	if (molch_get_message_type(packet, packet_length) != PREKEY_MESSAGE) {
		return -2;
	}

	//get the user
	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_KEY_SIZE);
	user_store_node *user = user_store_find_node(users, receiver_public_signing_key_buffer);
	if (user == NULL) {
		return -5;
	}

	//get the public prekey from the message
	buffer_create_with_existing_array(public_prekey, (unsigned char*)(packet + sizeof(molch_message_type)), PUBLIC_KEY_SIZE);

	//buffers
	buffer_t *private_prekey = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *sender_public_ephemeral_buffer = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	conversation_t *conversation = NULL;

	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*)sender_public_signing_key, PUBLIC_KEY_SIZE);
	memset(sender_public_ephemeral_buffer->content, 1, sender_public_ephemeral_buffer->content_length); //filled with 1s for now TODO: this has to be changed later on
	memset(private_prekey->content, 1, private_prekey->content_length); //filled with 1s for now TODO: this has to be changed later on

	int status = 0;
	//create a fake conversation
	conversation = create_conversation(
			user->public_signing_key, //FIXME, this is bullshit, on purpose
			user->public_signing_key, //FIXME, this is bullshit, on purpose
			sender_public_signing_key_buffer,
			private_prekey,
			public_prekey,
			sender_public_ephemeral_buffer);
	if (conversation == NULL) {
		status = -1;
		goto cleanup;
	}

	//add it to the conversation store
	status = conversation_store_add(user->conversations, conversation);
	if (status != 0) {
		goto cleanup;
	}
	conversation = NULL;

	//copy the conversation id
	status = buffer_clone_to_raw(conversation_id, CONVERSATION_ID_SIZE, user->conversations->tail->id);
	if (status != 0) {
		conversation_store_remove(user->conversations, user->conversations->tail);
		goto cleanup;
	}

	status = molch_decrypt_message(message, message_length, packet, packet_length, conversation_id);
	if (status != 0) {
		free(*message);
		conversation_store_remove(user->conversations, user->conversations->tail);
		goto cleanup;
	}

	status = create_prekey_list(
			receiver_public_signing_key_buffer,
			prekey_list,
			prekey_list_length);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	if (conversation != NULL) {
		conversation_destroy(conversation);
	}
	buffer_destroy_from_heap(private_prekey);
	buffer_destroy_from_heap(sender_public_ephemeral_buffer);

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
//TODO DO ACTUAL ENCRYPTION IN HERE! (currently unencrypted)
int molch_encrypt_message(
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output, length of the packet
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id) {
	//find the conversation
	conversation_t *conversation = find_conversation(conversation_id);

	//create packet
	*packet_length = sizeof(molch_message_type) + conversation->ratchet->their_public_ephemeral->content_length + message_length;
	*packet = malloc(*packet_length);
	if (*packet == NULL) {
		return -1;
	}


	//fill it
	//(message type || ephemeral key || message)
	static const molch_message_type NORMAL = NORMAL_MESSAGE;
	memcpy(*packet, &NORMAL, sizeof(molch_message_type)); //message type
	memcpy( *packet + sizeof(molch_message_type), //receivers ephemeral key
			conversation->ratchet->their_public_ephemeral->content,
			conversation->ratchet->their_public_ephemeral->content_length);
	memcpy( *packet + sizeof(molch_message_type) + conversation->ratchet->their_public_ephemeral->content_length, //message itself
			message,
			message_length);

	return 0;
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
		const unsigned char * const conversation_id __attribute__((unused))) {
	if (packet_length < sizeof(molch_message_type)) {
		*message_length = 0;
		*message = NULL;
		return -10;
	}

	*message_length = packet_length - sizeof(molch_message_type) - PUBLIC_KEY_SIZE;

	*message = malloc(*message_length);
	memcpy(*message, packet + sizeof(molch_message_type) + PUBLIC_KEY_SIZE, *message_length);
	return 0;
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
