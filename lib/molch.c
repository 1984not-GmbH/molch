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

#include "molch.h"
#include "../buffer/buffer.h"
#include "user-store.h"
#include "spiced-random.h"

//global user store
static user_store *users = NULL;

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
		unsigned char * const public_identity_key, //output, crypto_box_PUBLICKEYBYTES
		unsigned char * const prekey_list, //output, needs to be 100 * crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES
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

	int status;
	//buffer to put all the private keys into (random numbers created using the random input
	//in combination with system provided random data)
	buffer_t *private_keys = buffer_create((PREKEY_AMOUNT + 1) * crypto_box_PUBLICKEYBYTES, 0);
	//buffer for the random input
	buffer_t *random_data_buffer = buffer_create_with_existing_array((unsigned char*) random_data, random_data_length);
	random_data_buffer->readonly = true;

	//create private keys
	status = spiced_random(private_keys, random_data_buffer, private_keys->buffer_length);
	if (status != 0) {
		buffer_clear(private_keys);
		return status;
	}

	//create key buffers with pointers to the respective parts of the 'private_keys' buffer's content
	buffer_t *private_identity = buffer_create_with_existing_array(private_keys->content, crypto_box_SECRETKEYBYTES);
	buffer_t *private_prekeys = buffer_create_with_existing_array(private_keys->content + crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);

	//now calculate the public identity key from the private identity key
	buffer_t *public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = crypto_scalarmult_base(public_identity->content, private_identity->content);
	if (status != 0) {
		//only clearing 'private_keys' because all of the other buffers
		//only contain pointers to other buffers
		buffer_clear(private_keys);
		return status;
	}

	//calculate all the public prekeys
	buffer_t *public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = crypto_scalarmult_base(public_prekeys->content + i * crypto_box_PUBLICKEYBYTES, private_prekeys->content + i * crypto_box_SECRETKEYBYTES);
		if (status != 0) {
			//only clearing 'private_keys' because all of the other buffers
			//only contain pointers to other buffers
			buffer_clear(private_keys);
			return status;
		}
	}

	//now create the user
	status = user_store_add(
			users,
			public_identity,
			private_identity,
			public_prekeys,
			private_prekeys);
	if (status != 0) {
		//only clearing 'private_keys' because all of the other buffers
		//only contain pointers to other buffers
		buffer_clear(private_keys);
		return status;
	}

	//only clearing 'private_keys' because all of the other buffers
	//only contain pointers to other buffers
	buffer_clear(private_keys);

	//copy the keys to the output
	status = buffer_copy_to_raw(public_identity_key, 0, public_identity, 0, public_identity->content_length);
	if (status != 0) {
		return -10;
	}

	status = buffer_copy_to_raw(prekey_list, 0, public_prekeys, 0, public_prekeys->content_length);
	if (status != 0) {
		return -10;
	}

	return 0;
}

/*
 * Destroy a user.
 */
//(although they are selfcontained, so maybe not)
int molch_destroy_user(const unsigned char * const public_identity_key) {
	if (users == NULL) {
		return -1;
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	buffer_t *public_identity_key_buffer = buffer_create_with_existing_array((unsigned char*)public_identity_key, crypto_box_PUBLICKEYBYTES);
	user_store_remove_by_key(users, public_identity_key_buffer);

	return 0;
}

/*
 * Get the number of users.
 */
size_t molch_user_count() {
	if (users == NULL) {
		return 0;
	}

	size_t user_count;
	sodium_mprotect_readonly(users);
	user_count = users->length;
	sodium_mprotect_noaccess(users);

	return user_count;
}

/*
 * Delete all users.
 */
void molch_destroy_all_users() {
	if (users != NULL) {
		user_store_clear(users);
	}
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

	sodium_mprotect_readonly(users);
	*count = users->length;
	sodium_mprotect_noaccess(users);

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
		const unsigned char * const prekey_list, //prekey list of the receiver (PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES)
		const unsigned char * const sender_public_identity, //identity of the sender (user)
		const unsigned char * const receiver_public_identity) { //identity of the receiver
	//randomly chose the PREKEY to use for sending
	uint32_t prekey_number = randombytes_uniform(PREKEY_AMOUNT);
	buffer_t *receiver_public_ephemeral = buffer_create_with_existing_array((unsigned char*)&prekey_list[crypto_box_PUBLICKEYBYTES * prekey_number], crypto_box_PUBLICKEYBYTES);

	buffer_t *sender_public_identity_buffer = buffer_create_with_existing_array((unsigned char*)sender_public_identity, crypto_box_PUBLICKEYBYTES);
	//get the user that matches the public identity key of the sender
	user_store_node *user = user_store_find_node(users, sender_public_identity_buffer);
	if (user == NULL) {
		return -1;
	}

	buffer_t *receiver_public_identity_buffer = buffer_create_with_existing_array((unsigned char*)receiver_public_identity, crypto_box_PUBLICKEYBYTES);

	//create ephemeral keys
	buffer_t *our_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *our_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	int status = crypto_box_keypair(our_public_ephemeral->content, our_private_ephemeral->content);
	if (status != 0) {
		return -2;
	}

	sodium_mprotect_readwrite(user);
	//start a conversation
	status = conversation_store_add(
			user->conversations,
			user->private_identity_key,
			user->public_identity_key,
			receiver_public_identity_buffer,
			our_private_ephemeral,
			our_public_ephemeral,
			receiver_public_ephemeral);

	//copy the conversation id
	if (status == 0) {
		status = buffer_clone_to_raw(conversation_id, CONVERSATION_ID_SIZE, user->conversations->tail->conversation->id);
		if (status != 0) {
			conversation_store_remove(user->conversations, user->conversations->tail);
		}
	}
	sodium_mprotect_noaccess(user);
	buffer_clear(our_private_ephemeral);
	if (status != 0) {
		return status;
	}

	//create the packet
	status = molch_encrypt_message(packet, packet_length, message, message_length, conversation_id);
	if (status != 0) {
		free(*packet);
		*packet_length = 0;
		return status;
	}

	//make message type PREKEY_MESSAGE
	static const molch_message_type PREKEY = PREKEY_MESSAGE;
	memcpy(*packet, &PREKEY, sizeof(molch_message_type));

	return 0;
}

/*
 * Find out the position a prekey is in.
 *
 * Returns SIZE_MAX if it wasn't found.
 */
size_t get_prekey_number(const buffer_t * const prekeys, const buffer_t * const prekey) {
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare(prekey, &prekeys[i]) == 0) {
			//prekey found
			return i;
		}
	}

	return SIZE_MAX; //prekey not found
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
		unsigned char * const prekey_list __attribute__((unused)), //TODO: use thisoutput, needs to be PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES, This is the new prekey list for the receiving user
		const unsigned char * const sender_public_identity, //identity of the sender
		const unsigned char * const receiver_public_identity) { //identity key of the receiver (user)
	//check packet size
	if (packet_length < (sizeof(molch_message_type) + crypto_box_PUBLICKEYBYTES)) {
		return -1;
	}

	//check packet type
	if (molch_get_message_type(packet, packet_length) != PREKEY_MESSAGE) {
		return -2;
	}

	//get the user
	buffer_t *receiver_public_identity_buffer = buffer_create_with_existing_array((unsigned char*)receiver_public_identity, crypto_box_PUBLICKEYBYTES);
	user_store_node *user = user_store_find_node(users, receiver_public_identity_buffer);
	if (user == NULL) {
		return -5;
	}

	//get the public prekey from the message
	buffer_t *public_prekey = buffer_create_with_existing_array((unsigned char*)(packet + sizeof(molch_message_type)), crypto_box_PUBLICKEYBYTES);
	sodium_mprotect_readwrite(user);
	size_t prekey_number = get_prekey_number(user->public_prekeys, public_prekey);
	if (prekey_number == SIZE_MAX) { //prekey not found
		sodium_mprotect_noaccess(user);
		return -3;
	}

	//get the corresponding private prekey
	buffer_t *private_prekey = buffer_create(crypto_box_SECRETKEYBYTES, 0);
	int status = buffer_clone(private_prekey, &user->private_prekeys[prekey_number]);
	if (status != 0) {
		sodium_mprotect_noaccess(user);
		return status;
	}

	buffer_t *sender_public_identity_buffer = buffer_create_with_existing_array((unsigned char*)sender_public_identity, crypto_box_PUBLICKEYBYTES);
	buffer_t *sender_public_ephemeral_buffer = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	memset(sender_public_ephemeral_buffer->content, 1, sender_public_ephemeral_buffer->content_length); //filled with 1s for now TODO: this has to be changed later on

	//create a new conversation
	status = conversation_store_add(
			user->conversations,
			user->private_identity_key,
			user->public_identity_key,
			sender_public_identity_buffer,
			private_prekey,
			public_prekey,
			sender_public_ephemeral_buffer);
	buffer_clear(private_prekey);
	if (status != 0) {
		sodium_mprotect_noaccess(user);
		return status;
	}

	//copy the conversation id
	status = buffer_clone_to_raw(conversation_id, CONVERSATION_ID_SIZE, user->conversations->tail->conversation->id);
	if (status != 0) {
		conversation_store_remove(user->conversations, user->conversations->tail);
		sodium_mprotect_noaccess(user);
		return status;
	}

	status = molch_decrypt_message(message, message_length, packet, packet_length, conversation_id);
	if (status != 0) {
		free(*message);
		conversation_store_remove(user->conversations, user->conversations->tail);
		sodium_mprotect_noaccess(user);
		return status;
	}
	sodium_mprotect_noaccess(user);

	return 0;
}

/*
 * Find a conversation based on it's conversation id.
 */
conversation_t *find_conversation(const unsigned char * const conversation_id) {
	buffer_t *conversation_id_buffer = buffer_create_with_existing_array((unsigned char*)conversation_id, CONVERSATION_ID_SIZE);

	//go through all the users
	sodium_mprotect_readonly(users);
	user_store_node *node = users->head;
	conversation_store_node *conversation_node = NULL;
	while (node != NULL) {
		sodium_mprotect_readonly(node);
		conversation_node = conversation_store_find_node(node->conversations, conversation_id_buffer);
		if (conversation_node != NULL) {
			//found the conversation where searching for
			sodium_mprotect_noaccess(node);
			break;
		}
		user_store_node *next = node->next;
		sodium_mprotect_noaccess(node);
		node = next;
	}
	sodium_mprotect_noaccess(users);

	return conversation_node->conversation;
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

	*message_length = packet_length - sizeof(molch_message_type) - crypto_box_PUBLICKEYBYTES;

	*message = malloc(*message_length);
	memcpy(*message, packet + sizeof(molch_message_type) + crypto_box_PUBLICKEYBYTES, *message_length);
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
	sodium_mprotect_readwrite(user);
	conversation_store_remove_by_id(user->conversations, conversation->id);
	sodium_mprotect_noaccess(user);
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
	buffer_t *user_public_identity_buffer = buffer_create_with_existing_array((unsigned char*)user_public_identity, crypto_box_PUBLICKEYBYTES);
	user_store_node *user = user_store_find_node(users, user_public_identity_buffer);
	if (user == NULL) {
		*number = SIZE_MAX;
		return NULL;
	}

	sodium_mprotect_readonly(user);
	buffer_t *conversation_id_buffer = conversation_store_list(user->conversations);
	sodium_mprotect_noaccess(user);

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
	unsigned char *pool_content = sodium_malloc(100000);
	mempool_t *pool = alloca(sizeof(mempool_t));
	buffer_init_with_pointer(
			pool,
			pool_content,
			100000,
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
	buffer_t *printed_json = mcJSON_PrintBuffered(json, 100000, false);
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
	buffer_t *json_buffer = buffer_create_with_existing_array((unsigned char*)json, length);

	//parse the json
	//FIXME: Don't allocate fixed amount
	mcJSON *json_tree = mcJSON_ParseBuffered(json_buffer, 100000);
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
