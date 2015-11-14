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
//TODO this might also have to clear up conversations etc.
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
	while (molch_user_count() > 0) {
		size_t user_count;
		unsigned char *user_list = molch_user_list(&user_count);
		assert(user_count != 0);
		molch_destroy_user(user_list);
		free(user_list);
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
	unsigned char *user_list = malloc(user_list_buffer->content_length);
	*count = user_list_buffer->content_length / crypto_box_PUBLICKEYBYTES;
	int status = buffer_clone_to_raw(user_list, user_list_buffer->content_length, user_list_buffer);
	buffer_destroy_from_heap(user_list_buffer);
	if (status != 0) {
		*count = 0;
		free(user_list);
		return NULL;
	}

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
 * This requires a new set of prekeys from the receiver.
 */
molch_conversation molch_create_send_conversation(
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const prekey_list __attribute__((unused)), //prekey list of the receiver
		const unsigned char * const sender_public_identity, //identity of the sender (user)
		const unsigned char * const receiver_public_identity) { //identity of the receiver
	molch_conversation conversation;
	buffer_t *conversation_buffer = buffer_create_on_heap(2 * crypto_box_PUBLICKEYBYTES, 2 * crypto_box_PUBLICKEYBYTES);
	conversation.conversation = (void*) conversation_buffer;

	//copy public keys to conversation_buffer
	int status;
	status = buffer_copy_from_raw(conversation_buffer,
			0, //destination offset
			sender_public_identity,
			0, //source offset
			crypto_box_PUBLICKEYBYTES); //length
	if (status != 0) {
		conversation.valid = false;
		return conversation;
	}
	status = buffer_copy_from_raw(conversation_buffer,
			crypto_box_PUBLICKEYBYTES, //destination offset
			receiver_public_identity,
			0, //source offset
			crypto_box_PUBLICKEYBYTES); //length
	if (status != 0) {
		conversation.valid = false;
		return conversation;
	}

	//create the packet
	status = molch_encrypt_message(packet, packet_length, message, message_length, conversation);
	if (status != 0) {
		free(*packet);
		*packet_length = 0;
		conversation.valid = false;
		return conversation;
	}

	//make message type PREKEY_MESSAGE
	static const molch_message_type PREKEY = PREKEY_MESSAGE;
	memcpy(*packet, &PREKEY, sizeof(molch_message_type));

	conversation.valid = true;
	return conversation;
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
molch_conversation molch_create_receive_conversation(
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		const unsigned char * const prekey_list __attribute__((unused)), //output, needs to be 100 * crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES
		const unsigned char * const sender_public_identity, //identity of the sender
		const unsigned char * const receiver_public_identity) { //identity key of the receiver (user)
	molch_conversation conversation;
	buffer_t *conversation_buffer = buffer_create_on_heap(2 * crypto_box_PUBLICKEYBYTES, 2 * crypto_box_PUBLICKEYBYTES);
	conversation.conversation = (void*) conversation_buffer;

	//copy public keys to conversation_buffer
	int status;
	status = buffer_copy_from_raw(conversation_buffer,
			0, //destination offset
			sender_public_identity,
			0, //source offset
			crypto_box_PUBLICKEYBYTES); //length
	if (status != 0) {
		conversation.valid = false;
		return conversation;
	}
	status = buffer_copy_from_raw(conversation_buffer,
			crypto_box_PUBLICKEYBYTES, //destination offset
			receiver_public_identity,
			0, //source offset
			crypto_box_PUBLICKEYBYTES); //length
	if (status != 0) {
		conversation.valid = false;
		return conversation;
	}

	status = molch_decrypt_message(message, message_length, packet, packet_length, conversation);
	if (status != 0) {
		free(*message);
		*message_length = 0;
		conversation.valid = false;
		return conversation;
	}

	conversation.valid = true;
	return conversation;
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
		molch_conversation conversation __attribute__((unused))) {
	//create packet
	*packet_length = sizeof(molch_message_type) + message_length;
	*packet = malloc(*packet_length);

	//fill it
	static const molch_message_type NORMAL = NORMAL_MESSAGE;
	memcpy(*packet, &NORMAL, sizeof(molch_message_type));
	memcpy(*packet + sizeof(molch_message_type), message, message_length);

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
		molch_conversation conversation __attribute__((unused))) {
	if (packet_length < sizeof(molch_message_type)) {
		*message_length = 0;
		*message = NULL;
		return -10;
	}

	*message_length = packet_length - sizeof(molch_message_type);

	*message = malloc(*message_length);
	memcpy(*message, packet + sizeof(molch_message_type), *message_length);
	return 0;
}

/*
 * Destroy a conversation.
 *
 * This will almost certainly be changed later on!!!!!!
 */
void molch_destroy_conversation(molch_conversation conversation) {
	buffer_destroy_from_heap(((buffer_t*) conversation.conversation));
}
