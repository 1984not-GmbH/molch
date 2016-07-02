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

#include <stdbool.h>
#include "return-status.h"

#ifndef LIB_MOLCH_H
#define LIB_MOLCH_H

/*
 * THIS HEADER IS ONLY AN EARLY PREVIEW. IT WILL MOST CERTAINLY CHANGE IN THE FUTURE.
 */
/*
 * WARNING: ALTHOUGH THIS IMPLEMENTS THE AXOLOTL PROTOCOL, IT ISN't CONSIDERED SECURE ENOUGH TO USE AT THIS POINT
 */

/*
 * Create a new user. The user is identified by the public master key.
 *
 * Get's random input (can be in any format and doesn't have
 * to be uniformly distributed) and uses it in combination
 * with the OS's random number generator to generate a
 * signing and identity keypair for the user.
 *
 * IMPORTANT: Don't put random numbers provided by the operating
 * system in there.
 *
 * This also creates a signed list of prekeys to be uploaded to
 * the server.
 *
 * A new backup key is generated that subsequent backups of the library state will be encrypted with.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_create_user(
		unsigned char *const public_master_key, //output, PUBLIC_MASTER_KEY_SIZE
		const size_t public_master_key_length,
		unsigned char **const prekey_list, //output, needs to be freed
		size_t *const prekey_list_length,
		const unsigned char *const random_data,
		const size_t random_data_length,
		unsigned char * backup_key, //output, BACKUP_KEY_SIZE
		const size_t backup_key_length,
		unsigned char **const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length //optional, can be NULL
	) __attribute__((warn_unused_result));

/*
 * Destroy a user.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		unsigned char **const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use
		size_t *const backup_length //optional, can be NULL
);

/*
 * Get the number of users.
 */
size_t molch_user_count();

/*
 * List all of the users (list of the public keys),
 * NULL if there are no users.
 *
 * This list is heap allocated, so don't forget to free it.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_user_list(
		unsigned char **const user_list,
		size_t * const user_list_length, //length in bytes
		size_t *count);

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
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_create_send_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		const size_t conversation_id_length,
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const prekey_list, //prekey list of the receiver
		const size_t prekey_list_length,
		const unsigned char * const sender_public_master_key, //signing key of the sender (user)
		const size_t sender_public_master_key_length,
		const unsigned char * const receiver_public_master_key, //signing key of the receiver
		const size_t receiver_public_master_key_length,
		unsigned char ** const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length //optional, can be NULL
		) __attribute__((warn_unused_result));

/*
 * Start a new conversation. (receiving)
 *
 * This also generates a new set of prekeys to be uploaded to the server.
 *
 * This function is called after receiving a prekey message.
 *
 * The conversation can be identified by it's ID
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_create_receive_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		const size_t conversation_id_length,
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		unsigned char ** const prekey_list, //output, free after use
		size_t * const prekey_list_length,
		const unsigned char * const sender_public_master_key, //signing key of the sender
		const size_t sender_public_master_key_length,
		const unsigned char * const receiver_public_master_key, //signing key of the receiver (user)
		const size_t receiver_public_master_key_length,
		unsigned char ** const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length //optional, can be NULL
		) __attribute__((warn_unused_result));

/*
 * Encrypt a message and create a packet that can be sent to the receiver.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_encrypt_message(
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output, length of the packet
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id,
		unsigned char ** const backup, //optional, can be NULL, exports the conversationn, free after use, check if NULL before use!
		size_t * const backup_length
		) __attribute__((warn_unused_result));

/*
 * Decrypt a message.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_decrypt_message(
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t *message_length, //output
		const unsigned char * const packet, //received packet
		const size_t packet_length,
		const unsigned char * const conversation_id,
		uint32_t * const receive_message_number, //output
		uint32_t * const previous_receive_message_number, //output
		unsigned char ** const backup, //optional, can be NULL, exports the conversation, free after use, check if NULL before use!
		size_t * const backup_length
		) __attribute__((warn_unused_result));

/*
 * End a conversation.
 *
 * This will almost certainly be changed later on!!!!!!
 */
void molch_end_conversation(
		const unsigned char * const conversation_id,
		unsigned char ** const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length
		);

/*
 * List the conversations of a user.
 *
 * Returns the number of conversations and a list of conversations for a given user.
 * (all the conversation ids in one big list).
 *
 * Don't forget to free conversation_list after use.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_list_conversations(
		const unsigned char * const user_public_signing_key,
		unsigned char ** const conversation_list,
		size_t *number) __attribute__((warn_unused_result));

/*
 * Print a return status into a nice looking error message.
 *
 * Don't forget to free the output after use.
 */
char *molch_print_status(return_status status, size_t * const output_length) __attribute__((warn_unused_result));

/*
 * Get a string describing the return status type.
 *
 * (return_status.status)
 */
const char *molch_print_status_type(status_type type);

/*
 * Destroy a return status (only needs to be called if there was an error).
 */
void molch_destroy_return_status(return_status * const status);

/*
 * Serialize a conversation.
 *
 * Don't forget to free the output after use.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_conversation_export(
		unsigned char ** const backup,
		const unsigned char * const conversation_id,
		size_t * const length) __attribute__((warn_unused_result));

/*
 * Serialise molch's internal state. The output is encrypted with the backup key.
 *
 * Don't forget to free the output after use.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_export(
		unsigned char ** const backup, //output, free after use
		size_t *length) __attribute__((warn_unused_result));

/*
 * Import a conversation from a backup (overwrites the current one if it exists).
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_conversation_import(
		const unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * backup_key, //BACKUP_KEY_SIZE
		unsigned char * new_backup_key //output, BACKUP_KEY_SIZE, can be the same pointer as the backup key
		) __attribute__((warn_unused_result));

/*
 * Import molch's internal state from a backup (overwrites the current state)
 * and generates a new backup key.
 *
 * The backup key is needed to decrypt the backup.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_import(
		unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * const backup_key, //BACKUP_KEY_SIZE
		unsigned char * const new_backup_key //output, BACKUP_KEY_SIZE, can be the same pointer as the backup key
		) __attribute__((warn_unused_result));

/*
 * Get a signed list of prekeys for a given user.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_get_prekey_list(
		unsigned char * const public_signing_key,
		unsigned char ** const prekey_list,  //output, free after use
		size_t * const prekey_list_length) __attribute__((warn_unused_result));

/*
 * Generate and return a new key for encrypting the exported library state.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_update_backup_key(unsigned char * const new_key /*output with length of BACKUP_KEY_SIZE */) __attribute__((warn_unused_result));
#endif
