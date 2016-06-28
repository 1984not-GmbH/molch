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
#include "endianness.h"
#include "return-status.h"

//global user store
static user_store *users = NULL;
static buffer_t *backup_key = NULL;

//function prototypes
return_status molch_json_import(const unsigned char* const json, const size_t length) __attribute__((warn_unused_result));
return_status molch_json_export(
		unsigned char ** const json,
		size_t *length) __attribute__((warn_unused_result));

/*
 * Create a prekey list.
 */
return_status create_prekey_list(
		const buffer_t * const public_signing_key,
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length) {

	return_status status = return_status_init();

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
	user_store_node *user = NULL;
	status = user_store_find_node(&user, users, public_signing_key);
	throw_on_error(NOT_FOUND, "Failed to find user.");

	//get the public identity key
	status = master_keys_get_identity_key(
			user->master_keys,
			public_identity_key);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get public identity key from master keys.");

	//copy the public identity to the prekey list
	if (buffer_copy(unsigned_prekey_list, 0, public_identity_key, 0, PUBLIC_KEY_SIZE) != 0) {
		throw(BUFFER_ERROR, "Failed to copy public identity to prekey list.");
	}

	//get the prekeys
	status = prekey_store_list(user->prekeys, prekeys);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get prekeys.");

	//add the timestamp
	time_t timestamp = time(NULL);
	buffer_create_with_existing_array(big_endian_timestamp, unsigned_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_to_big_endian(timestamp, big_endian_timestamp);
	throw_on_error(CONVERSION_ERROR, "Failed to convert timestamp to big endian.");
	unsigned_prekey_list->content_length = unsigned_prekey_list->buffer_length;

	//sign the prekey list with the current identity key
	status = master_keys_sign(
			user->master_keys,
			unsigned_prekey_list,
			prekey_list_buffer);
	throw_on_error(SIGN_ERROR, "Failed to sign prekey list.");

	*prekey_list = prekey_list_buffer->content;
	*prekey_list_length = prekey_list_buffer->content_length;

cleanup:
	if (status.status != SUCCESS) {
		free(prekey_list_buffer->content);
	}

	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(unsigned_prekey_list);
	free(prekey_list_buffer);

	return status;
}

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
		unsigned char **const prekey_list, //output, needs to be freed
		size_t *const prekey_list_length,
		const unsigned char *const random_data,
		const size_t random_data_length,
		unsigned char * backup_key, //output, BACKUP_KEY_SIZE
		unsigned char **const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length //optional, can be NULL
) {
	return_status status = return_status_init();
	bool user_store_created = false;

	//create buffers wrapping the raw arrays
	buffer_create_with_existing_array(random_data_buffer, (unsigned char*)random_data, random_data_length);
	buffer_create_with_existing_array(public_master_key_buffer, public_master_key, PUBLIC_MASTER_KEY_SIZE);

	//create user store if it doesn't exist already
	if (users == NULL) {
		if (sodium_init() == -1) {
			throw(INIT_ERROR, "Failed to init libsodium.");
		}
		status = user_store_create(&users);
		throw_on_error(CREATION_ERROR, "Failed to create user store.")
	}

	//create a new backup key
	status = molch_update_backup_key(backup_key);
	throw_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//create the user
	status = user_store_create_user(
			users,
			random_data_buffer,
			public_master_key_buffer,
			NULL);
	throw_on_error(CREATION_ERROR, "Failed to create user.");

	user_store_created = true;

	status = create_prekey_list(
			public_master_key_buffer,
			prekey_list,
			prekey_list_length);
	throw_on_error(CREATION_ERROR, "Failed to create prekey list.");

	if (backup != NULL) {
		if (backup_length == 0) {
			*backup = NULL;
		} else {
			status = molch_export(backup, backup_length);
			throw_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	if ((status.status != SUCCESS) && user_store_created) {
		return_status new_status = molch_destroy_user(public_master_key, NULL, NULL);
		return_status_destroy_errors(&new_status);
	}

	return status;
}

/*
 * Destroy a user.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_destroy_user(
		const unsigned char *const public_signing_key,
		unsigned char **const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length //optional, can be NULL
) {
	return_status status = return_status_init();

	if (users == NULL) {
		throw(INVALID_INPUT, "\"users\" is NULL.")
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	buffer_create_with_existing_array(public_signing_key_buffer, (unsigned char*)public_signing_key, PUBLIC_KEY_SIZE);
	status = user_store_remove_by_key(users, public_signing_key_buffer);
	throw_on_error(REMOVE_ERROR, "Failed to remoe user from user store by key.");

	if (backup != NULL) {
		if (backup_length == 0) {
			*backup = NULL;
		} else {
			status = molch_export(backup, backup_length);
			throw_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	return status;
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
 *
 * The list is accessible via the return status' 'data' property.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_user_list(unsigned char **const user_list, size_t *count) {
	return_status status = return_status_init();

	if (users == NULL) {
		throw(INVALID_INPUT, "\"users\" is NULL.");
	}

	//get the list of users and copy it
	buffer_t *user_list_buffer = NULL;
	status = user_store_list(&user_list_buffer, users);
	throw_on_error(CREATION_ERROR, "Failed to create user list.");

	*count = molch_user_count();

	*user_list = user_list_buffer->content;
	free(user_list_buffer); //free the buffer_t struct while leaving content intact

cleanup:
	return status;
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
	return_status status = packet_get_metadata_without_verification(
		packet_buffer,
		&packet_type,
		&current_protocol_version,
		&highest_supported_protocol_version,
		&header_length,
		NULL,
		NULL,
		NULL);
	on_error(
		return_status_destroy_errors(&status);
		return INVALID;
	)

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
return_status verify_prekey_list(
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		buffer_t * const public_identity_key, //output, PUBLIC_KEY_SIZE
		const buffer_t * const public_signing_key
		) {
	return_status status = return_status_init();

	buffer_t *verified_prekey_list = buffer_create_on_heap(prekey_list_length - SIGNATURE_SIZE, prekey_list_length - SIGNATURE_SIZE);

	int status_int = 0;

	//verify the signature
	unsigned long long verified_length;
	status_int = crypto_sign_open(
			verified_prekey_list->content,
			&verified_length,
			prekey_list,
			(unsigned long long)prekey_list_length,
			public_signing_key->content);
	if (status_int != 0) {
		throw(VERIFICATION_FAILED, "Failed to verify prekey list signature.");
	}
	verified_prekey_list->content_length = verified_length;

	//get the timestamp
	time_t timestamp;
	buffer_create_with_existing_array(big_endian_timestamp, verified_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_from_big_endian(&timestamp, big_endian_timestamp);
	throw_on_error(CONVERSION_ERROR, "Failed to convert timestamp to big endian.");

	//make sure the prekey list isn't to old
	time_t current_time = time(NULL);
	if ((timestamp + 3600 * 24 * 31 * 3) < current_time) { //timestamp is older than 3 months
		throw(OUTDATED, "Timestamp is too old (older than 3 months).");
	}

	//copy the public identity key
	status_int = buffer_copy(
			public_identity_key,
			0,
			verified_prekey_list,
			0,
			PUBLIC_KEY_SIZE);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy public identity.");
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
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_create_send_conversation(
		unsigned char *const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		unsigned char **const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output
		const unsigned char *const message,
		const size_t message_length,
		const unsigned char *const prekey_list, //prekey list of the receiver (PREKEY_AMOUNT * PUBLIC_KEY_SIZE)
		const size_t prekey_list_length,
		const unsigned char *const sender_public_signing_key, //signing key of the sender (user)
		const unsigned char *const receiver_public_signing_key, //signing key of the receiver
		unsigned char **const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length //optional, can be NULL
) {
	//create buffers wrapping the raw input
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(message_buffer, (unsigned char*)message, message_length);
	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*)sender_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(prekeys, (unsigned char*)prekey_list + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t));

	//create buffers
	buffer_t *sender_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	conversation_t *conversation = NULL;
	buffer_t *packet_buffer = NULL;
	user_store_node *user = NULL;

	return_status status = return_status_init();

	//check input
	if ((conversation_id == NULL)
			|| (packet == NULL)
			|| (packet_length == NULL)
			|| (prekey_list == NULL)
			|| (sender_public_signing_key == NULL)
			|| (receiver_public_signing_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_create_send_conversation.");
	}

	//get the user that matches the public signing key of the sender
	status = user_store_find_node(&user, users, sender_public_signing_key_buffer);
	throw_on_error(NOT_FOUND, "User not found.");

	int status_int = 0;

	//get the receivers public ephemeral and identity
	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_identity,
			receiver_public_signing_key_buffer);
	throw_on_error(VERIFICATION_FAILED, "Failed to verify prekey list.");

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	//create the conversation and encrypt the message
	status = conversation_start_send_conversation(
			&conversation,
			message_buffer,
			&packet_buffer,
			user->master_keys->public_identity_key,
			user->master_keys->private_identity_key,
			receiver_public_identity,
			prekeys);
	throw_on_error(CREATION_ERROR, "Failed to start send converstion.");

	//copy the conversation id
	status_int = buffer_clone(conversation_id_buffer, conversation->id);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to clone conversation id.");
	}

	status = conversation_store_add(user->conversations, conversation);
	throw_on_error(ADDITION_ERROR, "Failed to add conversation to the users conversation store.");
	conversation = NULL;

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

	if (backup != NULL) {
		if (backup_length == 0) {
			*backup = NULL;
		} else {
			status = molch_export(backup, backup_length);
			throw_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

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

	if (status.status != SUCCESS) {
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
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_create_receive_conversation(
		unsigned char * const conversation_id, //output, CONVERSATION_ID_SIZE long (from conversation.h)
		unsigned char ** const message, //output, will be malloced by the function, don't forget to free it after use!
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		unsigned char ** const prekey_list, //output, free after use
		size_t * const prekey_list_length,
		const unsigned char * const sender_public_signing_key, //signing key of the sender
		const unsigned char * const receiver_public_signing_key, //signing key of the receiver (user)
		unsigned char ** const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length //optional, can be NULL
		) {

	return_status status = return_status_init();

	//create buffers to wrap the raw arrays
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);
	buffer_create_with_existing_array(sender_public_signing_key_buffer, (unsigned char*) sender_public_signing_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_signing_key_buffer, (unsigned char*)receiver_public_signing_key, PUBLIC_MASTER_KEY_SIZE);

	conversation_t *conversation = NULL;
	buffer_t *message_buffer = NULL;
	user_store_node *user = NULL;

	//get the user that matches the public signing key of the receiver
	status = user_store_find_node(&user, users, receiver_public_signing_key_buffer);
	throw_on_error(NOT_FOUND, "User not found in the user store.");

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	int status_int = 0;

	//create the conversation
	status = conversation_start_receive_conversation(
			&conversation,
			packet_buffer,
			&message_buffer,
			user->master_keys->public_identity_key,
			user->master_keys->private_identity_key,
			user->prekeys);
	throw_on_error(CREATION_ERROR, "Failed to start receive conversation.");

	//copy the conversation id
	status_int = buffer_clone(conversation_id_buffer, conversation->id);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to clone conversation id.");
	}

	//create the prekey list
	status = create_prekey_list(
			receiver_public_signing_key_buffer,
			prekey_list,
			prekey_list_length);
	throw_on_error(CREATION_ERROR, "Failed to create prekey list.");

	//add the conversation to the conversation store
	status = conversation_store_add(user->conversations, conversation);
	throw_on_error(ADDITION_ERROR, "Failed to add conversation to the users conversation store.");
	conversation = NULL;

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;

	if (backup != NULL) {
		if (backup_length == 0) {
			*backup = NULL;
		} else {
			status = molch_export(backup, backup_length);
			throw_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	if (status.status != SUCCESS) {
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
return_status find_conversation(
		conversation_t ** const conversation, //output
		const unsigned char * const conversation_id,
		conversation_store ** const conversation_store //optional, can be NULL, the conversation store where the conversation is in
		) {
	return_status status = return_status_init();

	conversation_t *conversation_node = NULL;

	if ((conversation == NULL) || (conversation_id == NULL)) {
		throw(INVALID_INPUT, "Invalid input for find_conversation.");
	}

	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);

	//go through all the users
	user_store_node *node = users->head;
	while (node != NULL) {
		status = conversation_store_find_node(&conversation_node, node->conversations, conversation_id_buffer);
		throw_on_error(GENERIC_ERROR, "Failure while searching for node.");
		if (conversation_node != NULL) {
			//found the conversation where searching for
			break;
		}
		user_store_node *next = node->next;
		node = next;
	}

	if (conversation_node == NULL) {
		goto cleanup;
	}

	if (conversation_store != NULL) {
		*conversation_store = node->conversations;
	}

cleanup:
	if (status.status != SUCCESS) {
		if (conversation != NULL) {
			*conversation = NULL;
		}
	} else {
		*conversation = conversation_node;
	}

	return status;
}

/*
 * Encrypt a message and create a packet that can be sent to the receiver.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_encrypt_message(
		unsigned char ** const packet, //output, will be malloced by the function, don't forget to free it after use!
		size_t *packet_length, //output, length of the packet
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id,
		unsigned char ** const json_export_conversation, //optional, can be NULL, exports the conversation as json, free with sodium_free, check if NULL before use!
		size_t * const json_export_conversation_length //optional, can be NULL
		) {

	//create buffer for message array
	buffer_create_with_existing_array(message_buffer, (unsigned char*) message, message_length);

	buffer_t *packet_buffer = NULL;
	conversation_t *conversation = NULL;

	return_status status = return_status_init();

	//find the conversation
	status = find_conversation(&conversation, conversation_id, NULL);
	throw_on_error(GENERIC_ERROR, "Error while searching for conversation.");
	if (conversation == NULL) {
		throw(NOT_FOUND, "Failed to find a conversation for the given ID.");
	}

	status = conversation_send(
			conversation,
			message_buffer,
			&packet_buffer,
			NULL,
			NULL,
			NULL);
	throw_on_error(GENERIC_ERROR, "Failed to send message.");

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

	if (json_export_conversation != NULL) {
		if (json_export_conversation_length == 0) {
			*json_export_conversation = NULL;
		} else {
			status = molch_conversation_json_export(json_export_conversation, conversation->id->content, json_export_conversation_length);
			throw_on_error(EXPORT_ERROR, "Failed to export conversation as JSON.");
		}
	}

cleanup:
	if (status.status != SUCCESS) {
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
 * Don't forget to destroy the return status with return_status_destroy_errors()
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
		unsigned char ** const json_export_conversation, //optional, can be NULL, exports the conversation as json, free with sodium_free, check if NULL before use!
		size_t * const json_export_conversation_length //optional, can be NULL
	) {
	//create buffer for the packet
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);

	return_status status = return_status_init();

	buffer_t *message_buffer = NULL;
	conversation_t *conversation = NULL;

	//find the conversation
	status = find_conversation(&conversation, conversation_id, NULL);
	throw_on_error(GENERIC_ERROR, "Error while searching for conversation.");
	if (conversation == NULL) {
		throw(NOT_FOUND, "Failed to find conversation with the given ID.");
	}

	status = conversation_receive(
			conversation,
			packet_buffer,
			receive_message_number,
			previous_receive_message_number,
			&message_buffer);
	throw_on_error(GENERIC_ERROR, "Failed to receive message.");

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;

	if (json_export_conversation != NULL) {
		if (json_export_conversation_length == 0) {
			*json_export_conversation = NULL;
		} else {
			status = molch_conversation_json_export(json_export_conversation, conversation->id->content, json_export_conversation_length);
			throw_on_error(EXPORT_ERROR, "Failed to export conversation as JSON.");
		}
	}

cleanup:
	if (status.status != SUCCESS) {
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
void molch_end_conversation(
		const unsigned char * const conversation_id,
		unsigned char ** const backup, //optional, can be NULL, exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length
		) {
	return_status status = return_status_init();

	//find the conversation
	conversation_t *conversation = NULL;
	status = find_conversation(&conversation, conversation_id, NULL);
	on_error(
		return_status_destroy_errors(&status);
		return;
	);
	if (conversation == NULL) {
		return;
	}
	//find the corresponding user
	user_store_node *user = NULL;
	status = user_store_find_node(&user, users, conversation->ratchet->our_public_identity);
	on_error(
		return_status_destroy_errors(&status);
		return;
	)
	conversation_store_remove_by_id(user->conversations, conversation->id);

	if (backup != NULL) {
		if (backup_length == 0) {
			*backup = NULL;
		} else {
			return_status status = molch_export(backup, backup_length);
			if (status.status != SUCCESS) {
				*backup = NULL;
			}
			return_status_destroy_errors(&status);
		}
	}
}

/*
 * List the conversations of a user.
 *
 * Returns the number of conversations and a list of conversations for a given user.
 * (all the conversation ids in one big list).
 *
 * Don't forget to free conversation_list after use.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_list_conversations(
		const unsigned char * const user_public_identity,
		unsigned char ** const conversation_list,
		size_t *number) {
	buffer_create_with_existing_array(user_public_identity_buffer, (unsigned char*)user_public_identity, PUBLIC_KEY_SIZE);
	buffer_t *conversation_list_buffer = NULL;

	return_status status = return_status_init();

	if ((user_public_identity == NULL) || (conversation_list == NULL) || (number == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_list_conversations.");
	}

	*conversation_list = NULL;

	user_store_node *user = NULL;
	status = user_store_find_node(&user, users, user_public_identity_buffer);
	throw_on_error(NOT_FOUND, "No user found for the given public identity.")

	status = conversation_store_list(&conversation_list_buffer, user->conversations);
	on_error(
		throw(DATA_FETCH_ERROR, "Failed to list conversations.");
	);
	if (conversation_list_buffer == NULL) {
		// list is empty
		*conversation_list = NULL;
		*number = 0;
		goto cleanup;
	}

	if ((conversation_list_buffer->content_length % CONVERSATION_ID_SIZE) != 0) {
		throw(INCORRECT_BUFFER_SIZE, "The conversation ID buffer has an incorrect length.");
	}
	*number = conversation_list_buffer->content_length / CONVERSATION_ID_SIZE;

	*conversation_list = conversation_list_buffer->content;
	free(conversation_list_buffer); //free buffer_t struct
	conversation_list_buffer = NULL;

cleanup:
	if (status.status != SUCCESS) {
		if (number != NULL) {
			*number = 0;
		}

		if (conversation_list_buffer != NULL) {
			buffer_destroy_from_heap(conversation_list_buffer);
		}
	}

	return status;
}

/*
 * Print a return status into a nice looking error message.
 *
 * Don't forget to free the output after use.
 */
char *molch_print_status(return_status status, size_t * const output_length) {
	return return_status_print(&status, output_length);
}

/*
 * Get a string describing the return status type.
 *
 * (return_status.status)
 */
const char *molch_print_status_type(status_type type) {
	return return_status_get_name(type);
}

/*
 * Destroy a return status (only needs to be called if there was an error).
 */
void molch_destroy_return_status(return_status * const status) {
	return_status_destroy_errors(status);
}

/*
 * Serialize a conversation into JSON.
 *
 * Use sodium_free to free json after use.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_conversation_json_export(
		unsigned char ** const json,
		const unsigned char * const conversation_id, size_t * const length) {

	//set allocation functions of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	return_status status = return_status_init();

	mempool_t *json_string = NULL;
	mempool_t *pool = NULL;

	//check input
	if ((conversation_id == NULL) || (length == NULL) || (json == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_conversation_json_export");
	}

	conversation_t *conversation = NULL;
	status = find_conversation(&conversation, conversation_id, NULL);
	throw_on_error(GENERIC_ERROR, "Error while searching for conversation.");
	if (conversation == NULL) {
		throw(NOT_FOUND, "No conversation found for the given ID.");
	}

	mcJSON *json_tree = NULL;

	//allocate a memory pool
	//FIXME: Don't allocate a fixed amount
	pool = buffer_create_with_custom_allocator(1000000, 0, sodium_malloc, sodium_free);
	if (pool == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate memory pool.");
	}

	json_tree = conversation_json_export(conversation, pool);
	if (json_tree == NULL) {
		throw(EXPORT_ERROR, "Failed to export conversation as JSON.");
	}

	//print to string
	//FIXME: Don't allocate a fixed amount
	json_string = mcJSON_PrintBuffered(json_tree, 100000, false);
	if (json_string == NULL) {
		throw(GENERIC_ERROR, "Failed to print JSON.");
	}

	*length = json_string->content_length;
	*json = json_string->content;
	sodium_free(json_string);

cleanup:
	if (pool != NULL) {
		buffer_destroy_with_custom_deallocator(pool, sodium_free);
	}

	if (status.status != SUCCESS) {
		if (length != NULL) {
			*length = 0;
		}

		if (json_string != NULL) {
			buffer_destroy_with_custom_deallocator(json_string, sodium_free);
		}
	}

	return status;
}

/*
 * Import a conversation from JSON (overwrites the current one if it exists).
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_conversation_json_import(const unsigned char * const json, const size_t length) {
	return_status status = return_status_init();

	//set allocation function of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	mcJSON *json_tree = NULL;
	conversation_t *imported_conversation = NULL;
	//create a buffer for the conversation id
	buffer_t *conversation_id = buffer_create_on_heap(CONVERSATION_ID_SIZE, 0);

	if (json == NULL) {
		throw(INVALID_INPUT, "\"json\" is NULL.");
	}

	//create a buffer for the JSON string
	buffer_create_with_existing_array(json_buffer, (unsigned char*)json, length);


	int status_int = 0;

	//parse the json
	json_tree = mcJSON_ParseBuffered(json_buffer, 100000);
	if (json_tree == NULL) {
		throw(IMPORT_ERROR, "Failed to parse JSON.");
	}

	//get the conversation id
	buffer_create_from_string(id_string, "id");
	mcJSON *conversation_id_json = mcJSON_GetObjectItem(json_tree, id_string);
	if ((conversation_id_json == NULL) || (conversation_id_json->type != mcJSON_String) || (conversation_id_json->valuestring->content_length != (2 * CONVERSATION_ID_SIZE + 1))) {
		throw(IMPORT_ERROR, "Invalid JSON.");
	}

	status_int = buffer_clone_from_hex(conversation_id, conversation_id_json->valuestring);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to clone conversation ID.");
	}

	//import the conversation
	imported_conversation = conversation_json_import(json_tree);
	if (imported_conversation == NULL) {
		throw(IMPORT_ERROR, "Failed to import conversation.");
	}

	//search the conversation in the conversation store
	conversation_store *store = NULL;
	conversation_t *old_conversation = NULL;
	status = find_conversation(&old_conversation, conversation_id->content, &store);
	on_error(
		molch_end_conversation(conversation_id->content, NULL, NULL);
		throw(GENERIC_ERROR, "Error while searching for conversation.");
	);
	if (old_conversation != NULL) { //destroy the old one if it exists
		molch_end_conversation(conversation_id->content, NULL, NULL);
	}

	if (store == NULL) {
		throw(NOT_FOUND, "No conversation store to put the conversation into.");
	}

	//now add the conversation to the store
	status = conversation_store_add(store, imported_conversation);
	throw_on_error(ADDITION_ERROR, "Failed to add conversation to the conversation store.");

cleanup:
	if (status.status != SUCCESS) {
		if (json_tree != NULL) {
			sodium_free(json_tree);
		}

		if (imported_conversation != NULL) {
			conversation_destroy(imported_conversation);
		}
	}

	buffer_destroy_from_heap(conversation_id);

	return status;
}

/*
 * Serialise molch's state into JSON.
 *
 * Use sodium_free to free json after use.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_json_export(
		unsigned char ** const json,
		size_t *length) {
	//set allocation functions of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	mempool_t *pool = NULL;
	buffer_t *json_string = NULL;

	return_status status = return_status_init();

	if ((json == NULL) || (length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_json_export.");
	}

	// empty array when there is no content
	if (users == NULL) {
		*json = sodium_malloc(sizeof("[]"));
		strncpy((char*)*json, "[]", sizeof("[]"));
		*length = sizeof("[]");
		goto cleanup;
	}

	//allocate a memory pool
	//FIXME: Don't allocate a fixed amount
	pool = buffer_create_with_custom_allocator(5000000, 0, sodium_malloc, sodium_free);
	if (pool == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate memory pool.");
	}

	//serialize state into tree of mcJSON objects
	mcJSON *json_tree = user_store_json_export(users, pool);
	if (json_tree == NULL) {
		throw(EXPORT_ERROR, "Failed to export user store to JSON.");
	}

	//print to string
	//FIXME: Don't allocate a fixed amount (that's the only way to do it right now unfortunately)
	json_string = mcJSON_PrintBuffered(json_tree, 5000000, false);
	if (json_string == NULL) {
		throw(GENERIC_ERROR, "Failed to print JSON.");
	}

	*length = json_string->content_length;
	*json = json_string->content;
	sodium_free(json_string); //free the buffer_t struct (leaving content intact)

cleanup:
	if (pool != NULL) {
		buffer_destroy_with_custom_deallocator(pool, sodium_free);
	}

	if (status.status != SUCCESS) {
		if (length != 0) {
			*length = 0;
		}

		if (json_string != NULL) {
			buffer_destroy_with_custom_deallocator(json_string, sodium_free);
		}
	}

	return status;
}

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
		size_t *length) {
	return_status status = return_status_init();

	unsigned char *json = NULL;
	size_t json_length = 0;

	//buffers
	buffer_t *backup_buffer = NULL;
	buffer_t *backup_nonce = buffer_create_on_heap(BACKUP_NONCE_SIZE, 0);

	if ((backup == NULL) || (length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_export.");
	}

	if ((backup_key == NULL) || (backup_key->content_length == 0)) {
		throw(INCORRECT_DATA, "No backup key found.");
	}

	status = molch_json_export(&json, &json_length);
	throw_on_error(EXPORT_ERROR, "Failed to export the library state to JSON.");

	backup_buffer = buffer_create_on_heap(json_length + BACKUP_NONCE_SIZE + crypto_secretbox_MACBYTES, json_length + BACKUP_NONCE_SIZE + crypto_secretbox_MACBYTES);
	if (backup_buffer == NULL) {
		throw(ALLOCATION_FAILED, "Failed to create backup buffer.");
	}

	//generate the nonce
	if (buffer_fill_random(backup_nonce, BACKUP_NONCE_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to generate backup nonce.");
	}

	//encrypt the JSON
	int status_int = crypto_secretbox_easy(
			backup_buffer->content,
			json,
			json_length,
			backup_nonce->content,
			backup_key->content);
	if (status_int != 0) {
		throw(ENCRYPT_ERROR, "Failed to encrypt library state.");
	}

	//copy the nonce at the end of the output
	status_int = buffer_copy_to_raw(
			backup_buffer->content,
			json_length + crypto_secretbox_MACBYTES,
			backup_nonce,
			0,
			BACKUP_NONCE_SIZE);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy nonce to backup.");
	}

	*backup = backup_buffer->content;
	*length = backup_buffer->content_length;

	free(backup_buffer);

cleanup:
	on_error(
		if (backup_buffer != NULL) {
			buffer_destroy_from_heap(backup_buffer);
		}
	);

	buffer_destroy_from_heap(backup_nonce);
	if (json != NULL) {
		sodium_free(json);
	}

	return status;
}

/*
 * Import the molch's state from JSON (overwrites the current state!)
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_json_import(const unsigned char *const json, const size_t length){
	//set allocation functions of mcJSON to the libsodium allocation functions
	mcJSON_Hooks allocation_functions = {
		sodium_malloc,
		sodium_free
	};
	mcJSON_InitHooks(&allocation_functions);

	user_store *users_backup = NULL;

	return_status status = return_status_init();

	//initialize libsodium if not done already
	if (users == NULL) {
		if (sodium_init() == -1) {
			throw(INIT_ERROR, "Failed to initialise libsodium.");
		}
	}

	//create buffer for the json string
	buffer_create_with_existing_array(json_buffer, (unsigned char*)json, length);

	//parse the json
	//FIXME: Don't allocate fixed amount
	mcJSON *json_tree = mcJSON_ParseBuffered(json_buffer, 5000000);
	if (json_tree == NULL) {
		throw(IMPORT_ERROR, "Failed to parse JSON.");
	}

	//backup the old user_store
	users_backup = users;

	//import the user store from json
	users = user_store_json_import(json_tree);
	if (users == NULL) {
		throw(IMPORT_ERROR, "Failed to import user store from JSON.");
	}

	if (users_backup != NULL) {
		user_store_destroy(users_backup);
		users_backup = NULL;
	}

cleanup:
	on_error(
		if (users_backup != NULL) {
			users = users_backup; //roll back backup
		}
	);

	return status;
}

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
		const unsigned char * const local_backup_key, //BACKUP_KEY_SIZE
		unsigned char * const new_backup_key //BACKUP_KEY_SIZE, can be the same pointer as the backup key
		) {
	return_status status = return_status_init();

	buffer_t *json = buffer_create_with_custom_allocator(backup_length, 0, sodium_malloc, sodium_free);

	//check input
	if ((backup == NULL) || (local_backup_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_import.");
	}


	//check the lengths
	if (backup_length < BACKUP_NONCE_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Backup is too short.");
	}

	size_t json_length = backup_length - BACKUP_NONCE_SIZE - crypto_secretbox_MACBYTES;

	//decrypt the backup
	int status_int = crypto_secretbox_open_easy(
			json->content,
			backup,
			backup_length - BACKUP_NONCE_SIZE,
			backup + backup_length - BACKUP_NONCE_SIZE,
			local_backup_key);
	if (status_int != 0) {
		throw(DECRYPT_ERROR, "Failed to decrypt backup.");
	}

	json->content_length = json_length;

	status = molch_update_backup_key(new_backup_key);
	throw_on_error(KEYGENERATION_FAILED, "Faild to generate a new backup key.");

	status = molch_json_import(
			json->content,
			json->content_length);
	throw_on_error(IMPORT_ERROR, "Failed to import from decrypted JSON.");

cleanup:
	buffer_destroy_with_custom_deallocator(json, sodium_free);

	return status;
}

/*
 * Get a signed list of prekeys for a given user.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_get_prekey_list(
		unsigned char * const public_signing_key,
		unsigned char ** const prekey_list,  //output, free after use
		size_t * const prekey_list_length) {
	return_status status = return_status_init();

	// check input
	if ((public_signing_key == NULL) || (prekey_list == NULL) || (prekey_list_length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_get_prekey_list.");
	}

	buffer_create_with_existing_array(public_signing_key_buffer, public_signing_key, PUBLIC_MASTER_KEY_SIZE);

	status = create_prekey_list(
			public_signing_key_buffer,
			prekey_list,
			prekey_list_length);
	throw_on_error(CREATION_ERROR, "Failed to create prekey list.");

cleanup:
	return status;
}

/*
 * Generate and return a new key for encrypting the exported library state.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_update_backup_key(unsigned char * const new_key /*output with length of BACKUP_KEY_SIZE */) {
	return_status status = return_status_init();

	buffer_create_with_existing_array(new_key_buffer, new_key, BACKUP_KEY_SIZE);

	if (new_key == NULL) {
		throw(INVALID_INPUT, "Invalid input to molch_update_backup_key.");
	}

	// create a backup key buffer if it doesnt exist already
	if (backup_key == NULL) {
		backup_key = buffer_create_with_custom_allocator(BACKUP_KEY_SIZE, 0, sodium_malloc, sodium_free);
		if (backup_key == NULL) {
			throw(CREATION_ERROR, "Failed to create backup key buffer.");
		}
	}

	//make backup key buffer writable
	if (sodium_mprotect_readwrite(backup_key) != 0) {
		throw(GENERIC_ERROR, "Failed to make backup key readwrite.");
	}
	//make the content of the backup key writable
	if (sodium_mprotect_readwrite(backup_key->content) != 0) {
		throw(GENERIC_ERROR, "Failed to make backup key content readwrite.");
	}

	if (buffer_fill_random(backup_key, BACKUP_KEY_SIZE) != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate new backup key.");
	}

	if (buffer_clone(new_key_buffer, backup_key) != 0) {
		throw(BUFFER_ERROR, "Failed to copy new backup key.");
	}

cleanup:
	if (backup_key != NULL) {
		sodium_mprotect_readonly(backup_key);
		sodium_mprotect_readonly(backup_key->content);
	}

	return status;
}
