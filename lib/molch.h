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

#include <stdbool.h>

#ifndef LIB_MOLCH_H
#define LIB_MOLCH_H

/*
 * THIS HEADER IS ONLY AN EARLY PREVIEW. IT WILL MOST CERTAINLY CHANGE IN THE FUTURE.
 */

/*
 * Create a new user. The user is identified by the public master key.
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
		unsigned char * const prekey_list, //output, needs to be 100 * PUBLIC_KEY_SIZE
		const unsigned char * const random_data,
		const size_t random_data_length) __attribute__((warn_unused_result));

/*
 * Destroy a user.
 */
int molch_destroy_user(
		const unsigned char * const public_identity_key);

/*
 * Get the number of users.
 */
size_t molch_user_count();

/*
 * List all of the users (list of the public keys),
 * NULL if there are no users.
 *
 * This list is heap allocated, so don't forget to free it.
 */
unsigned char* molch_user_list(size_t *count);

/*
 * Delete all users.
 */
void molch_destroy_all_users();

typedef enum molch_message_type { PREKEY_MESSAGE, NORMAL_MESSAGE, INVALID } molch_message_type;

/*
 * Get the type of a message.
 *
 * This is either a normal message or a prekey message.
 * Prekey messages mark the start of a new conversation.
 */
molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length);

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
		const unsigned char * const sender_public_identity, //identity of the sender (user)
		const unsigned char * const receiver_public_identity) __attribute__((warn_unused_result));  //identity of the receiver
//prekeys of the receiver (PREKEY_AMOUNT * PUBLIC_KEY_SIZE)

/*
 * Start a new conversation. (receiving)
 *
 * This also generates a new set of prekeys to be uploaded to the server.
 *
 * This function is called after receiving a prekey message.
 *
 * The conversation can be identified by it's ID
 *
 * conversation->valid is false on failure
 *
 * Returns 0 on success.
 */
int molch_create_receive_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		unsigned char * const prekey_list, //output, needs to be PREKEY_AMOUNT * PUBLIC_KEY_SIZE + crypto_onetimeauth_BYTES, This is the new prekey list for the receiving user
		const unsigned char * const sender_public_identity, //identity of the sender
		const unsigned char * const receiver_public_identity) __attribute__((warn_unused_result)); //identity key of the receiver (user)

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
		const unsigned char * const conversation_id) __attribute__((warn_unused_result));

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
		const unsigned char * const conversation_id) __attribute__((warn_unused_result));

/*
 * End a conversation.
 *
 * This will almost certainly be changed later on!!!!!!
 */
void molch_end_conversation(const unsigned char * const conversation_id);

/*
 * List the conversations of a user.
 *
 * Returns the number of conversations and a list of conversations for a given user.
 * (all the conversation ids in one big list).
 *
 * Don't forget to free it after use.
 *
 * Returns NULL if the user doesn't exist or if there is no conversation.
 */
unsigned char *molch_list_conversations(const unsigned char * const user_public_identity, size_t *number) __attribute__((warn_unused_result));

/*
 * Serialise molch's state into JSON.
 *
 * Returns NULL on failure.
 */
unsigned char *molch_json_export(size_t *length) __attribute__((warn_unused_result));

/*
 * Import the molch's state from JSON (overwrites the current state!)
 *
 * Returns 0 on success.
 */
int molch_json_import(const unsigned char* const json, const size_t length) __attribute__((warn_unused_result));
#endif
