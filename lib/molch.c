/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
#include "zeroed_malloc.h"

#include <encrypted_backup.pb-c.h>
#include <backup.pb-c.h>

//global user store
static user_store *users = NULL;
static buffer_t *backup_key = NULL;

/*
 * Create a prekey list.
 */
return_status create_prekey_list(
		const buffer_t * const public_signing_key,
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length) {

	return_status status = return_status_init();

	//create buffers
	buffer_t *unsigned_prekey_list = NULL;
	buffer_t *prekey_list_buffer = NULL;
	buffer_t *public_identity_key = NULL;
	unsigned_prekey_list = buffer_create_on_heap(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t),
			0);
	throw_on_failed_alloc(unsigned_prekey_list);
	prekey_list_buffer = buffer_create_on_heap(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t) + SIGNATURE_SIZE,
			0);
	throw_on_failed_alloc(prekey_list_buffer);
	public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	throw_on_failed_alloc(public_identity_key);

	//buffer for the prekey part of unsigned_prekey_list
	buffer_create_with_existing_array(prekeys, unsigned_prekey_list->content + PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);


	//get the user
	user_store_node *user = NULL;
	status = user_store_find_node(&user, users, public_signing_key);
	throw_on_error(NOT_FOUND, "Failed to find user.");

	//rotate the prekeys
	status = prekey_store_rotate(user->prekeys);
	throw_on_error(GENERIC_ERROR, "Failed to rotate prekeys.");

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

	//add the expiration date
	time_t expiration_date = time(NULL) + 3600 * 24 * 31 * 3; //the prekey list will expire in 3 months
	buffer_create_with_existing_array(big_endian_expiration_date, unsigned_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_to_big_endian(expiration_date, big_endian_expiration_date);
	throw_on_error(CONVERSION_ERROR, "Failed to convert expiration date to big endian.");
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
	on_error(
		if (prekey_list_buffer != NULL) {
			free(prekey_list_buffer->content);
		}
	)

	buffer_destroy_from_heap_and_null_if_valid(public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(unsigned_prekey_list);
	free_and_null_if_valid(prekey_list_buffer);

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
		//outputs
		unsigned char *const public_master_key, //PUBLIC_MASTER_KEY_SIZE
		const size_t public_master_key_length,
		unsigned char **const prekey_list, //needs to be freed
		size_t *const prekey_list_length,
		unsigned char * backup_key, //BACKUP_KEY_SIZE
		const size_t backup_key_length,
		//optional output (can be NULL)
		unsigned char **const backup, //exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length,
		//optional input (can be NULL)
		const unsigned char *const random_data,
		const size_t random_data_length) {
	return_status status = return_status_init();
	bool user_store_created = false;

	if ((public_master_key == NULL)
		|| (prekey_list == NULL) || (prekey_list_length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_create_user.");
	}

	if (backup_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Backup key has incorrect length.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Public master key has incorrect length.");
	}

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
	status = molch_update_backup_key(backup_key, backup_key_length);
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
	on_error(
		if (user_store_created) {
			return_status new_status = molch_destroy_user(public_master_key, public_master_key_length, NULL, NULL);
			return_status_destroy_errors(&new_status);
		}
	)

	return status;
}

/*
 * Destroy a user.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		//optional output (can be NULL)
		unsigned char **const backup, //exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length
) {
	return_status status = return_status_init();

	if (users == NULL) {
		throw(INVALID_INPUT, "\"users\" is NULL.")
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Public master key has incorrect size.");
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	buffer_create_with_existing_array(public_signing_key_buffer, (unsigned char*)public_master_key, PUBLIC_KEY_SIZE);
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
		user_store_destroy(users);
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
return_status molch_list_users(
		unsigned char **const user_list,
		size_t * const user_list_length, //length in bytes
		size_t * const count) {
	return_status status = return_status_init();

	if ((users == NULL) || (user_list_length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_list_users.");
	}

	//get the list of users and copy it
	buffer_t *user_list_buffer = NULL;
	status = user_store_list(&user_list_buffer, users);
	throw_on_error(CREATION_ERROR, "Failed to create user list.");

	*count = molch_user_count();

	*user_list = user_list_buffer->content;
	*user_list_length = user_list_buffer->content_length;
	free_and_null_if_valid(user_list_buffer); //free the buffer_t struct while leaving content intact

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

	molch_message_type packet_type;
	uint32_t current_protocol_version;
	uint32_t highest_supported_protocol_version;
	return_status status = packet_get_metadata_without_verification(
		&current_protocol_version,
		&highest_supported_protocol_version,
		&packet_type,
		packet_buffer,
		NULL,
		NULL,
		NULL);
	on_error(
		return_status_destroy_errors(&status);
		return INVALID;
	)

	return packet_type;
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
	throw_on_failed_alloc(verified_prekey_list);

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

	//get the expiration date
	time_t expiration_date;
	buffer_create_with_existing_array(big_endian_expiration_date, verified_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
	status = endianness_time_from_big_endian(&expiration_date, big_endian_expiration_date);
	throw_on_error(CONVERSION_ERROR, "Failed to convert expiration date to big endian.");

	//make sure the prekey list isn't too old
	time_t current_time = time(NULL);
	if (expiration_date < current_time) {
		throw(OUTDATED, "Prekey list has expired (older than 3 months).");
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
	buffer_destroy_from_heap_and_null_if_valid(verified_prekey_list);

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
return_status molch_start_send_conversation(
		//outputs
		unsigned char *const conversation_id, //CONVERSATION_ID_SIZE long (from conversation.h)
		const size_t conversation_id_length,
		unsigned char **const packet, //free after use
		size_t *packet_length,
		//inputs
		const unsigned char *const sender_public_master_key, //signing key of the sender (user)
		const size_t sender_public_master_key_length,
		const unsigned char *const receiver_public_master_key, //signing key of the receiver
		const size_t receiver_public_master_key_length,
		const unsigned char *const prekey_list, //prekey list of the receiver
		const size_t prekey_list_length,
		const unsigned char *const message,
		const size_t message_length,
		//optional output (can be NULL)
		unsigned char **const backup, //exports the entire library state, free after use, check if NULL before use!
		size_t *const backup_length
) {
	//create buffers wrapping the raw input
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(message_buffer, (unsigned char*)message, message_length);
	buffer_create_with_existing_array(sender_public_master_key_buffer, (unsigned char*)sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_master_key_buffer, (unsigned char*)receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(prekeys, (unsigned char*)prekey_list + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t));

	conversation_t *conversation = NULL;
	buffer_t *packet_buffer = NULL;
	user_store_node *user = NULL;

	return_status status = return_status_init();

	//create buffers
	buffer_t *sender_public_identity = NULL;
	buffer_t *receiver_public_identity = NULL;
	buffer_t *receiver_public_ephemeral = NULL;
	sender_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	throw_on_failed_alloc(sender_public_identity);
	receiver_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	throw_on_failed_alloc(receiver_public_identity);
	receiver_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	throw_on_failed_alloc(receiver_public_ephemeral);

	//check input
	if ((conversation_id == NULL)
			|| (packet == NULL)
			|| (packet_length == NULL)
			|| (prekey_list == NULL)
			|| (sender_public_master_key == NULL)
			|| (receiver_public_master_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_start_send_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "conversation id has incorrect size.");
	}

	if (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "sender public master key has incorrect size.");
	}

	if (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "receiver public master key has incorrect size.");
	}

	//get the user that matches the public signing key of the sender
	status = user_store_find_node(&user, users, sender_public_master_key_buffer);
	throw_on_error(NOT_FOUND, "User not found.");

	int status_int = 0;

	//get the receivers public ephemeral and identity
	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_identity,
			receiver_public_master_key_buffer);
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
	buffer_destroy_from_heap_and_null_if_valid(sender_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(receiver_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(receiver_public_ephemeral);

	if (conversation != NULL) {
		conversation_destroy(conversation);
	}

	if (user != NULL) {
		sodium_mprotect_noaccess(user->master_keys);
	}

	on_error(
		if (packet_buffer != NULL) {
			//not using free_and_null_if_valid because content is const
			free(packet_buffer->content);
		}
	)

	free_and_null_if_valid(packet_buffer);

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
return_status molch_start_receive_conversation(
		//outputs
		unsigned char * const conversation_id, //CONVERSATION_ID_SIZE long (from conversation.h)
		const size_t conversation_id_length,
		unsigned char ** const prekey_list, //free after use
		size_t * const prekey_list_length,
		unsigned char ** const message, //free after use
		size_t * const message_length,
		//inputs
		const unsigned char * const receiver_public_master_key, //signing key of the receiver (user)
		const size_t receiver_public_master_key_length,
		const unsigned char * const sender_public_master_key, //signing key of the sender
		const size_t sender_public_master_key_length,
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		//optional output (can be NULL)
		unsigned char ** const backup, //exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length
		) {

	return_status status = return_status_init();

	//create buffers to wrap the raw arrays
	buffer_create_with_existing_array(conversation_id_buffer, (unsigned char*)conversation_id, CONVERSATION_ID_SIZE);
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);
	buffer_create_with_existing_array(sender_public_master_key_buffer, (unsigned char*) sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_with_existing_array(receiver_public_master_key_buffer, (unsigned char*)receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);

	conversation_t *conversation = NULL;
	buffer_t *message_buffer = NULL;
	user_store_node *user = NULL;

	if ((conversation_id == NULL)
		|| (message == NULL) || (message_length == NULL)
		|| (packet == NULL)
		|| (prekey_list == NULL) || (prekey_list_length == NULL)
		|| (sender_public_master_key == NULL)
		|| (receiver_public_master_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_start_receive_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

	if (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Senders public master key has an incorrect size.");
	}

	if (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Receivers public master key has an incorrect size.");
	}

	//get the user that matches the public signing key of the receiver
	status = user_store_find_node(&user, users, receiver_public_master_key_buffer);
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
			receiver_public_master_key_buffer,
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
	on_error(
		if (message_buffer != NULL) {
			free(message_buffer->content);
		}
	)

	free_and_null_if_valid(message_buffer);

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
		//output
		unsigned char ** const packet, //free after use
		size_t *packet_length,
		//inputs
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		const unsigned char * const message,
		const size_t message_length,
		//optional output (can be NULL)
		unsigned char ** const conversation_backup, //exports the conversation, free after use, check if NULL before use!
		size_t * const conversation_backup_length
		) {

	//create buffer for message array
	buffer_create_with_existing_array(message_buffer, (unsigned char*) message, message_length);

	buffer_t *packet_buffer = NULL;
	conversation_t *conversation = NULL;

	return_status status = return_status_init();

	if ((packet == NULL) || (packet_length == NULL)
		|| (message == NULL)
		|| (conversation_id == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_encrypt_message.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

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

	if (conversation_backup != NULL) {
		if (conversation_backup_length == 0) {
			*conversation_backup = NULL;
		} else {
			status = molch_conversation_export(conversation_backup, conversation_backup_length, conversation->id->content, conversation->id->content_length);
			throw_on_error(EXPORT_ERROR, "Failed to export conversation as JSON.");
		}
	}

cleanup:
	on_error(
		if (packet_buffer != NULL) {
			// not using free_and_null_if_valid because content is const
			free(packet_buffer->content);
		}
	)

	free_and_null_if_valid(packet_buffer);

	return status;
}

/*
 * Decrypt a message.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_decrypt_message(
		//outputs
		unsigned char ** const message, //free after use
		size_t *message_length,
		uint32_t * const receive_message_number,
		uint32_t * const previous_receive_message_number,
		//inputs
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		const unsigned char * const packet,
		const size_t packet_length,
		//optional output (can be NULL)
		unsigned char ** const conversation_backup, //exports the conversation, free after use, check if NULL before use!
		size_t * const conversation_backup_length
	) {
	//create buffer for the packet
	buffer_create_with_existing_array(packet_buffer, (unsigned char*)packet, packet_length);

	return_status status = return_status_init();

	buffer_t *message_buffer = NULL;
	conversation_t *conversation = NULL;

	if ((message == NULL) || (message_length == NULL)
		|| (packet == NULL)
		|| (conversation_id == NULL)
		|| (receive_message_number == NULL)
		|| (previous_receive_message_number == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_decrypt_message.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

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

	if (conversation_backup != NULL) {
		if (conversation_backup_length == 0) {
			*conversation_backup = NULL;
		} else {
			status = molch_conversation_export(conversation_backup, conversation_backup_length, conversation->id->content, conversation->id->content_length);
			throw_on_error(EXPORT_ERROR, "Failed to export conversation as JSON.");
		}
	}

cleanup:
	on_error(
		if (message_buffer != NULL) {
			// not using free_and_null_if_valid because content is const
			free(message_buffer->content);
		}
	)

	free_and_null_if_valid(message_buffer);

	return status;
}

/*
 * Destroy a conversation.
 *
 * This will almost certainly be changed later on!!!!!!
 */
void molch_end_conversation(
		//input
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		//optional output (can be NULL)
		unsigned char ** const backup, //exports the entire library state, free after use, check if NULL before use!
		size_t * const backup_length
		) {
	return_status status = return_status_init();

	if (conversation_id == NULL) {
		throw(INVALID_INPUT, "Invalid input to molch_end_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect length.");
	}

	//find the conversation
	conversation_t *conversation = NULL;
	status = find_conversation(&conversation, conversation_id, NULL);
	throw_on_error(NOT_FOUND, "Couldn't find converstion.");

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
			on_error(
				*backup = NULL;
			)
		}
	}

cleanup:
	return_status_destroy_errors(&status);

	return;
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
		//outputs
		unsigned char ** const conversation_list,
		size_t * const conversation_list_length,
		size_t * const number,
		//inputs
		const unsigned char * const user_public_master_key,
		const size_t user_public_master_key_length) {
	buffer_create_with_existing_array(user_public_master_key_buffer, (unsigned char*)user_public_master_key, PUBLIC_KEY_SIZE);
	buffer_t *conversation_list_buffer = NULL;

	return_status status = return_status_init();

	if ((user_public_master_key == NULL) || (conversation_list == NULL) || (conversation_list_length == NULL) || (number == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_list_conversations.");
	}

	if (user_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Public master key has an incorrect length.");
	}

	*conversation_list = NULL;

	user_store_node *user = NULL;
	status = user_store_find_node(&user, users, user_public_master_key_buffer);
	throw_on_error(NOT_FOUND, "No user found for the given public identity.")

	status = conversation_store_list(&conversation_list_buffer, user->conversations);
	on_error(
		throw(DATA_FETCH_ERROR, "Failed to list conversations.");
	)
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
	*conversation_list_length = conversation_list_buffer->content_length;
	free(conversation_list_buffer); //free buffer_t struct
	conversation_list_buffer = NULL;

cleanup:
	on_error(
		if (number != NULL) {
			*number = 0;
		}

		buffer_destroy_from_heap_and_null_if_valid(conversation_list_buffer);
	)

	return status;
}

/*
 * Print a return status into a nice looking error message.
 *
 * Don't forget to free the output after use.
 */
char *molch_print_status(size_t * const output_length, return_status status) {
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
 * Serialize a conversation.
 *
 * Don't forget to free the output after use.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_conversation_export(
		//output
		unsigned char ** const backup,
		size_t * const backup_length,
		//input
		const unsigned char * const conversation_id,
		const size_t conversation_id_length) {
	return_status status = return_status_init();

	buffer_t *conversation_buffer = NULL;
	buffer_t *backup_nonce = NULL;
	buffer_t *backup_buffer = NULL;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	Conversation *conversation_struct = NULL;

	//check input
	if ((backup == NULL) || (backup_length == NULL)
			|| (conversation_id == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_conversation_export");
	}
	if ((conversation_id_length != CONVERSATION_ID_SIZE)) {
		throw(INVALID_INPUT, "Conversation ID has an invalid size.");
	}

	if ((backup_key == NULL) || (backup_key->content_length != BACKUP_KEY_SIZE)) {
		throw(INCORRECT_DATA, "No backup key found.");
	}

	//find the conversation
	conversation_t *conversation = NULL;
	status = find_conversation(&conversation, conversation_id, NULL);
	throw_on_error(NOT_FOUND, "Failed to find the conversation.");

	//export the conversation
	status = conversation_export(conversation, &conversation_struct);
	conversation = NULL; //remove alias
	throw_on_error(EXPORT_ERROR, "Failed to export conversation to protobuf-c struct.");

	//pack the struct
	const size_t conversation_size = conversation__get_packed_size(conversation_struct);
	conversation_buffer = buffer_create_with_custom_allocator(conversation_size, 0, zeroed_malloc, zeroed_free);
	throw_on_failed_alloc(conversation_buffer);

	conversation_buffer->content_length = conversation__pack(conversation_struct, conversation_buffer->content);
	if (conversation_buffer->content_length != conversation_size) {
		throw(PROTOBUF_PACK_ERROR, "Failed to pack conversation to protobuf-c.");
	}

	//generate the nonce
	backup_nonce = buffer_create_on_heap(BACKUP_NONCE_SIZE, 0);
	throw_on_failed_alloc(backup_nonce);
	if (buffer_fill_random(backup_nonce, BACKUP_NONCE_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to generaete backup nonce.");
	}

	//allocate the output
	backup_buffer = buffer_create_on_heap(conversation_size + crypto_secretbox_MACBYTES, conversation_size + crypto_secretbox_MACBYTES);
	throw_on_failed_alloc(backup_buffer);

	//encrypt the backup
	int status_int = crypto_secretbox_easy(
			backup_buffer->content,
			conversation_buffer->content,
			conversation_buffer->content_length,
			backup_nonce->content,
			backup_key->content);
	if (status_int != 0) {
		backup_buffer->content_length = 0;
		throw(ENCRYPT_ERROR, "Failed to enrypt conversation state.");
	}

	//fill in the encrypted backup struct
	//metadata
	encrypted_backup_struct.backup_version = 0;
	encrypted_backup_struct.has_backup_type = true;
	encrypted_backup_struct.backup_type = ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP;
	//nonce
	encrypted_backup_struct.has_encrypted_backup_nonce = true;
	encrypted_backup_struct.encrypted_backup_nonce.data = backup_nonce->content;
	encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce->content_length;
	//encrypted backup
	encrypted_backup_struct.has_encrypted_backup = true;
	encrypted_backup_struct.encrypted_backup.data = backup_buffer->content;
	encrypted_backup_struct.encrypted_backup.len = backup_buffer->content_length;

	//now pack the entire backup
	const size_t encrypted_backup_size = encrypted_backup__get_packed_size(&encrypted_backup_struct);
	*backup = malloc(encrypted_backup_size);
	*backup_length = encrypted_backup__pack(&encrypted_backup_struct, *backup);
	if (*backup_length != encrypted_backup_size) {
		throw(PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
	}

cleanup:
	on_error(
		if ((backup != NULL) && (*backup != NULL)) {
			free(*backup);
			*backup = NULL;
		}
		if (backup_length != NULL) {
			*backup_length = 0;
		}
	)

	if (conversation_struct != NULL) {
		conversation__free_unpacked(conversation_struct, &protobuf_c_allocators);
		conversation_struct = NULL;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(conversation_buffer, zeroed_free);
	buffer_destroy_from_heap_and_null_if_valid(backup_nonce);
	buffer_destroy_from_heap_and_null_if_valid(backup_buffer);

	return status;
}

/*
 * Import a conversation from a backup (overwrites the current one if it exists).
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_conversation_import(
		//output
		unsigned char * new_backup_key,
		const size_t new_backup_key_length,
		//inputs
		const unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * local_backup_key,
		const size_t local_backup_key_length) {
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = NULL;
	buffer_t *decrypted_backup = NULL;
	Conversation *conversation_struct = NULL;
	conversation_t *conversation = NULL;

	//check input
	if ((backup == NULL) || (local_backup_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_import.");
	}
	if (local_backup_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Backup key has an incorrect length.");
	}
	if (new_backup_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "New backup key has an incorrect length.");
	}

	//unpack the encrypted backup
	encrypted_backup_struct = encrypted_backup__unpack(&protobuf_c_allocators, backup_length, backup);
	if (encrypted_backup_struct == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		throw(INCORRECT_DATA, "Incompatible backup.");
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
		throw(INCORRECT_DATA, "Backup is not a conversation backup.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw(PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		throw(PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
	}

	decrypted_backup = buffer_create_with_custom_allocator(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, zeroed_malloc, zeroed_free);
	throw_on_failed_alloc(decrypted_backup);

	//decrypt the backup
	int status_int = crypto_secretbox_open_easy(
			decrypted_backup->content,
			encrypted_backup_struct->encrypted_backup.data,
			encrypted_backup_struct->encrypted_backup.len,
			encrypted_backup_struct->encrypted_backup_nonce.data,
			local_backup_key);
	if (status_int != 0) {
		throw(DECRYPT_ERROR, "Failed to decrypt conversation backup.");
	}

	//unpack the struct
	conversation_struct = conversation__unpack(&protobuf_c_allocators, decrypted_backup->content_length, decrypted_backup->content);
	if (conversation_struct == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversations protobuf-c.");
	}

	//import the conversation
	status = conversation_import(&conversation, conversation_struct);
	throw_on_error(IMPORT_ERROR, "Failed to import conversation from Protobuf-C struct.");

	conversation_store *containing_store = NULL;
	conversation_t *existing_conversation = NULL;
	status = find_conversation(&existing_conversation, conversation->id->content, &containing_store);
	throw_on_error(NOT_FOUND, "Imported conversation has to exist, but it doesn't.");

	status = conversation_store_add(containing_store, conversation);
	throw_on_error(ADDITION_ERROR, "Failed to add imported conversation to the conversation store.");
	conversation = NULL;


	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	on_error(
		//remove the new imported conversation
		conversation_store_remove(containing_store, conversation);
		throw(KEYGENERATION_FAILED, "Failed to update backup key.");
	)

	//everything worked, the old conversation can now be removed
	conversation_store_remove(containing_store, existing_conversation);

cleanup:
	if (encrypted_backup_struct != NULL) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = NULL;
	}
	if (conversation_struct != NULL) {
		conversation__free_unpacked(conversation_struct, &protobuf_c_allocators);
		conversation_struct = NULL;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(decrypted_backup, zeroed_free);
	if (conversation != NULL) {
		conversation_destroy(conversation);
		conversation = NULL;
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
		unsigned char ** const backup,
		size_t *backup_length) {
	return_status status = return_status_init();

	buffer_t *users_buffer = NULL;
	buffer_t *backup_nonce = NULL;
	buffer_t *backup_buffer = NULL;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	Backup *backup_struct = NULL;

	//check input
	if ((backup == NULL) || (backup_length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_export");
	}

	if ((backup_key == NULL) || (backup_key->content_length != BACKUP_KEY_SIZE)) {
		throw(INCORRECT_DATA, "No backup key found.");
	}

	backup_struct = zeroed_malloc(sizeof(Backup));
	throw_on_failed_alloc(backup_struct);
	backup__init(backup_struct);

	//export the conversation
	status = user_store_export(users, &(backup_struct->users), &(backup_struct->n_users));
	throw_on_error(EXPORT_ERROR, "Failed to export user store to protobuf-c struct.");

	//pack the struct
	const size_t backup_struct_size = backup__get_packed_size(backup_struct);
	users_buffer = buffer_create_with_custom_allocator(backup_struct_size, 0, zeroed_malloc, zeroed_free);
	throw_on_failed_alloc(users_buffer);

	users_buffer->content_length = backup__pack(backup_struct, users_buffer->content);
	if (users_buffer->content_length != backup_struct_size) {
		throw(PROTOBUF_PACK_ERROR, "Failed to pack conversation to protobuf-c.");
	}

	//generate the nonce
	backup_nonce = buffer_create_on_heap(BACKUP_NONCE_SIZE, 0);
	throw_on_failed_alloc(backup_nonce);
	if (buffer_fill_random(backup_nonce, BACKUP_NONCE_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to generaete backup nonce.");
	}

	//allocate the output
	backup_buffer = buffer_create_on_heap(backup_struct_size + crypto_secretbox_MACBYTES, backup_struct_size + crypto_secretbox_MACBYTES);
	throw_on_failed_alloc(backup_buffer);

	//encrypt the backup
	int status_int = crypto_secretbox_easy(
			backup_buffer->content,
			users_buffer->content,
			users_buffer->content_length,
			backup_nonce->content,
			backup_key->content);
	if (status_int != 0) {
		backup_buffer->content_length = 0;
		throw(ENCRYPT_ERROR, "Failed to enrypt conversation state.");
	}

	//fill in the encrypted backup struct
	//metadata
	encrypted_backup_struct.backup_version = 0;
	encrypted_backup_struct.has_backup_type = true;
	encrypted_backup_struct.backup_type = ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP;
	//nonce
	encrypted_backup_struct.has_encrypted_backup_nonce = true;
	encrypted_backup_struct.encrypted_backup_nonce.data = backup_nonce->content;
	encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce->content_length;
	//encrypted backup
	encrypted_backup_struct.has_encrypted_backup = true;
	encrypted_backup_struct.encrypted_backup.data = backup_buffer->content;
	encrypted_backup_struct.encrypted_backup.len = backup_buffer->content_length;

	//now pack the entire backup
	const size_t encrypted_backup_size = encrypted_backup__get_packed_size(&encrypted_backup_struct);
	*backup = malloc(encrypted_backup_size);
	*backup_length = encrypted_backup__pack(&encrypted_backup_struct, *backup);
	if (*backup_length != encrypted_backup_size) {
		throw(PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
	}

cleanup:
	on_error(
		if ((backup != NULL) && (*backup != NULL)) {
			free(*backup);
			*backup = NULL;
		}
		if (backup_length != NULL) {
			*backup_length = 0;
		}
	)

	if (backup_struct != NULL) {
		backup__free_unpacked(backup_struct, &protobuf_c_allocators);
		backup_struct = NULL;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(users_buffer, zeroed_free);
	buffer_destroy_from_heap_and_null_if_valid(backup_nonce);
	buffer_destroy_from_heap_and_null_if_valid(backup_buffer);

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
		//output
		unsigned char * const new_backup_key, //BACKUP_KEY_SIZE, can be the same pointer as the backup key
		const size_t new_backup_key_length,
		//inputs
		unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * const local_backup_key, //BACKUP_KEY_SIZE
		const size_t local_backup_key_length
		) {
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = NULL;
	buffer_t *decrypted_backup = NULL;
	Backup *backup_struct = NULL;
	user_store *store = NULL;

	//check input
	if ((backup == NULL) || (local_backup_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_import.");
	}
	if (local_backup_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Backup key has an incorrect length.");
	}
	if (new_backup_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "New backup key has an incorrect length.");
	}

	//unpack the encrypted backup
	encrypted_backup_struct = encrypted_backup__unpack(&protobuf_c_allocators, backup_length, backup);
	if (encrypted_backup_struct == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		throw(INCORRECT_DATA, "Incompatible backup.");
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
		throw(INCORRECT_DATA, "Backup is not a full backup.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw(PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted state.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		throw(PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
	}

	decrypted_backup = buffer_create_with_custom_allocator(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, zeroed_malloc, zeroed_free);
	throw_on_failed_alloc(decrypted_backup);

	//decrypt the backup
	int status_int = crypto_secretbox_open_easy(
			decrypted_backup->content,
			encrypted_backup_struct->encrypted_backup.data,
			encrypted_backup_struct->encrypted_backup.len,
			encrypted_backup_struct->encrypted_backup_nonce.data,
			local_backup_key);
	if (status_int != 0) {
		throw(DECRYPT_ERROR, "Failed to decrypt backup.");
	}

	//unpack the struct
	backup_struct = backup__unpack(&protobuf_c_allocators, decrypted_backup->content_length, decrypted_backup->content);
	if (backup_struct == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack backups protobuf-c.");
	}

	//import the user store
	status = user_store_import(&store, backup_struct->users, backup_struct->n_users);
	throw_on_error(IMPORT_ERROR, "Failed to import user store from Protobuf-C struct.");

	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	throw_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//everyting worked, switch to the new user store
	user_store_destroy(users);
	users = store;
	store = NULL;

cleanup:
	if (encrypted_backup_struct != NULL) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = NULL;
	}
	if (backup_struct != NULL) {
		backup__free_unpacked(backup_struct, &protobuf_c_allocators);
		backup_struct = NULL;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(decrypted_backup, zeroed_free);
	if (store != NULL) {
		user_store_destroy(store);
		store = NULL;
	}

	return status;
}

/*
 * Get a signed list of prekeys for a given user.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occured.
 */
return_status molch_get_prekey_list(
		//output
		unsigned char ** const prekey_list,  //free after use
		size_t * const prekey_list_length,
		//input
		unsigned char * const public_master_key,
		const size_t public_master_key_length) {
	return_status status = return_status_init();

	// check input
	if ((public_master_key == NULL) || (prekey_list == NULL) || (prekey_list_length == NULL)) {
		throw(INVALID_INPUT, "Invalid input to molch_get_prekey_list.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Public master key has an incorrect length.");
	}

	buffer_create_with_existing_array(public_signing_key_buffer, public_master_key, PUBLIC_MASTER_KEY_SIZE);

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
return_status molch_update_backup_key(
		unsigned char * const new_key, //output, BACKUP_KEY_SIZE
		const size_t new_key_length) {
	return_status status = return_status_init();

	buffer_create_with_existing_array(new_key_buffer, new_key, BACKUP_KEY_SIZE);

	if (users == NULL) {
		if (sodium_init() == -1) {
			throw(INIT_ERROR, "Failed to initialize libsodium.");
		}
	}

	if (new_key == NULL) {
		throw(INVALID_INPUT, "Invalid input to molch_update_backup_key.");
	}

	if (new_key_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "New key has an incorrect length.");
	}

	// create a backup key buffer if it doesnt exist already
	if (backup_key == NULL) {
		backup_key = buffer_create_with_custom_allocator(BACKUP_KEY_SIZE, 0, sodium_malloc, sodium_free);
		throw_on_failed_alloc(backup_key);
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
