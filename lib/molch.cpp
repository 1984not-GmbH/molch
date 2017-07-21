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

#include <cassert>
#include <cstdint>

#include "constants.h"
#include "molch.h"
#include "packet.h"
#include "buffer.h"
#include "user-store.h"
#include "endianness.h"
#include "return-status.h"
#include "zeroed_malloc.h"

extern "C" {
	#include <encrypted_backup.pb-c.h>
	#include <backup.pb-c.h>
}

//global user store
static user_store *users = nullptr;
static Buffer *global_backup_key = nullptr;

/*
 * Create a prekey list.
 */
static return_status create_prekey_list(
		Buffer * const public_signing_key,
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length) {

	return_status status = return_status_init();
	user_store_node *user = nullptr;

	//create buffers
	Buffer *unsigned_prekey_list = nullptr;
	Buffer *prekey_list_buffer = nullptr;
	Buffer *public_identity_key = nullptr;
	unsigned_prekey_list = Buffer::create(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t),
			0);
	THROW_on_failed_alloc(unsigned_prekey_list);
	prekey_list_buffer = Buffer::create(
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t) + SIGNATURE_SIZE,
			0);
	THROW_on_failed_alloc(prekey_list_buffer);
	public_identity_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(public_identity_key);

	{
		//buffer for the prekey part of unsigned_prekey_list
		Buffer prekeys(unsigned_prekey_list->content + PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);


		//get the user
		status = user_store_find_node(&user, users, public_signing_key);
		THROW_on_error(NOT_FOUND, "Failed to find user.");

		//rotate the prekeys
		status = user->prekeys->rotate();
		THROW_on_error(GENERIC_ERROR, "Failed to rotate prekeys.");

		//get the public identity key
		status = user->master_keys->getIdentityKey(*public_identity_key);
		THROW_on_error(DATA_FETCH_ERROR, "Failed to get public identity key from master keys.");

		//copy the public identity to the prekey list
		if (unsigned_prekey_list->copyFrom(0, public_identity_key, 0, PUBLIC_KEY_SIZE) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public identity to prekey list.");
		}

		//get the prekeys
		status = user->prekeys->list(prekeys);
		THROW_on_error(DATA_FETCH_ERROR, "Failed to get prekeys.");
	}

	//add the expiration date
	{
		int64_t expiration_date = time(nullptr) + 3600 * 24 * 31 * 3; //the prekey list will expire in 3 months
		Buffer big_endian_expiration_date(unsigned_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
		try {
			to_big_endian(expiration_date, big_endian_expiration_date);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
		unsigned_prekey_list->content_length = unsigned_prekey_list->getBufferLength();
	}

	//sign the prekey list with the current identity key
	status = user->master_keys->sign(*unsigned_prekey_list, *prekey_list_buffer);
	THROW_on_error(SIGN_ERROR, "Failed to sign prekey list.");

	*prekey_list = prekey_list_buffer->content;
	*prekey_list_length = prekey_list_buffer->content_length;

cleanup:
	on_error {
		if (prekey_list_buffer != nullptr) {
			free(prekey_list_buffer->content);
		}
	}

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
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length,
		//optional input (can be nullptr)
		const unsigned char *const random_data,
		const size_t random_data_length) {
	return_status status = return_status_init();
	bool user_store_created = false;
	//create buffers wrapping the raw arrays
	Buffer random_data_buffer(random_data, random_data_length);
	Buffer public_master_key_buffer(public_master_key, PUBLIC_MASTER_KEY_SIZE);


	if ((public_master_key == nullptr)
		|| (prekey_list == nullptr) || (prekey_list_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_create_user.");
	}

	if (backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Backup key has incorrect length.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has incorrect length.");
	}

	//create user store if it doesn't exist already
	if (users == nullptr) {
		if (sodium_init() == -1) {
			THROW(INIT_ERROR, "Failed to init libsodium.");
		}
		status = user_store_create(&users);
		THROW_on_error(CREATION_ERROR, "Failed to create user store.")
	}

	//create a new backup key
	status = molch_update_backup_key(backup_key, backup_key_length);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//create the user
	status = user_store_create_user(
			users,
			&random_data_buffer,
			&public_master_key_buffer,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to create user.");

	user_store_created = true;

	status = create_prekey_list(
			&public_master_key_buffer,
			prekey_list,
			prekey_list_length);
	THROW_on_error(CREATION_ERROR, "Failed to create prekey list.");

	if (backup != nullptr) {
		if (backup_length == 0) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	on_error {
		if (user_store_created) {
			return_status new_status = molch_destroy_user(public_master_key, public_master_key_length, nullptr, nullptr);
			return_status_destroy_errors(&new_status);
		}
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
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	return_status status = return_status_init();

	if (users == nullptr) {
		THROW(INVALID_INPUT, "\"users\" is nullptr.")
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has incorrect size.");
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	{
		Buffer public_signing_key_buffer(public_master_key, PUBLIC_MASTER_KEY_SIZE);
		status = user_store_remove_by_key(users, &public_signing_key_buffer);
		THROW_on_error(REMOVE_ERROR, "Failed to remoe user from user store by key.");
	}

	if (backup != nullptr) {
		if (backup_length == 0) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	return status;
}

/*
 * Get the number of users.
 */
size_t molch_user_count() {
	if (users == nullptr) {
		return 0;
	}

	return users->length;
}

/*
 * Delete all users.
 */
void molch_destroy_all_users() {
	if (users != nullptr) {
		user_store_destroy(users);
	}

	users = nullptr;
}

/*
 * List all of the users (list of the public keys),
 * nullptr if there are no users.
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

	if ((users == nullptr) || (user_list_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_list_users.");
	}

	//get the list of users and copy it
	{
		Buffer *user_list_buffer = nullptr;
		status = user_store_list(&user_list_buffer, users);
		THROW_on_error(CREATION_ERROR, "Failed to create user list.");

		*count = molch_user_count();

		*user_list = user_list_buffer->content;
		*user_list_length = user_list_buffer->content_length;
		free_and_null_if_valid(user_list_buffer); //free the Buffer struct while leaving content intact
	}

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
	Buffer packet_buffer(packet, packet_length);

	molch_message_type packet_type;
	uint32_t current_protocol_version;
	uint32_t highest_supported_protocol_version;
	return_status status = packet_get_metadata_without_verification(
		current_protocol_version,
		highest_supported_protocol_version,
		packet_type,
		packet_buffer,
		nullptr,
		nullptr,
		nullptr);
	on_error {
		return_status_destroy_errors(&status);
		return INVALID;
	}

	return packet_type;
}

/*
 * Verify prekey list and extract the public identity
 * and choose a prekey.
 */
static return_status verify_prekey_list(
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		Buffer * const public_identity_key, //output, PUBLIC_KEY_SIZE
		Buffer * const public_signing_key
		) {
	return_status status = return_status_init();

	Buffer *verified_prekey_list = Buffer::create(prekey_list_length - SIGNATURE_SIZE, prekey_list_length - SIGNATURE_SIZE);
	THROW_on_failed_alloc(verified_prekey_list);

	//verify the signature
	{
		unsigned long long verified_length;
		int status_int = crypto_sign_open(
				verified_prekey_list->content,
				&verified_length,
				prekey_list,
				(unsigned long long)prekey_list_length,
				public_signing_key->content);
		if (status_int != 0) {
			THROW(VERIFICATION_FAILED, "Failed to verify prekey list signature.");
		}
		if (verified_length > SIZE_MAX)
		{
			THROW(CONVERSION_ERROR, "Length is bigger than size_t.");
		}
		verified_prekey_list->content_length = (size_t)verified_length;
	}

	//get the expiration date
	{
		int64_t expiration_date;
		Buffer big_endian_expiration_date(verified_prekey_list->content + PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE, sizeof(int64_t));
		try {
			from_big_endian(expiration_date, big_endian_expiration_date);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//make sure the prekey list isn't too old
		{
			int64_t current_time = time(nullptr);
			if (expiration_date < current_time) {
				THROW(OUTDATED, "Prekey list has expired (older than 3 months).");
			}
		}
	}

	//copy the public identity key
	{
		int status_int = public_identity_key->copyFrom(0, verified_prekey_list, 0, PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public identity.");
		}
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
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	//create buffers wrapping the raw input
	Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
	Buffer message_buffer(message, message_length);
	Buffer sender_public_master_key_buffer(sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer receiver_public_master_key_buffer(receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer prekeys(prekey_list + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t));

	conversation_t *conversation = nullptr;
	Buffer *packet_buffer = nullptr;
	user_store_node *user = nullptr;

	return_status status = return_status_init();

	//create buffers
	Buffer *sender_public_identity = nullptr;
	Buffer *receiver_public_identity = nullptr;
	Buffer *receiver_public_ephemeral = nullptr;
	sender_public_identity = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(sender_public_identity);
	receiver_public_identity = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(receiver_public_identity);
	receiver_public_ephemeral = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(receiver_public_ephemeral);

	//check input
	if ((conversation_id == nullptr)
			|| (packet == nullptr)
			|| (packet_length == nullptr)
			|| (prekey_list == nullptr)
			|| (sender_public_master_key == nullptr)
			|| (receiver_public_master_key == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_start_send_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "conversation id has incorrect size.");
	}

	if (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "sender public master key has incorrect size.");
	}

	if (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "receiver public master key has incorrect size.");
	}

	//get the user that matches the public signing key of the sender
	status = user_store_find_node(&user, users, &sender_public_master_key_buffer);
	THROW_on_error(NOT_FOUND, "User not found.");

	//get the receivers public ephemeral and identity
	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_identity,
			&receiver_public_master_key_buffer);
	THROW_on_error(VERIFICATION_FAILED, "Failed to verify prekey list.");

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	//create the conversation and encrypt the message
	status = conversation_start_send_conversation(
			&conversation,
			&message_buffer,
			&packet_buffer,
			&user->master_keys->public_identity_key,
			&user->master_keys->private_identity_key,
			receiver_public_identity,
			&prekeys);
	THROW_on_error(CREATION_ERROR, "Failed to start send converstion.");

	//copy the conversation id
	{
		int status_int = conversation_id_buffer.cloneFrom(&conversation->id);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to clone conversation id.");
		}
	}

	status = user->conversations->add(conversation);
	THROW_on_error(ADDITION_ERROR, "Failed to add conversation to the users conversation store.");
	conversation = nullptr;

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

	if (backup != nullptr) {
		if (backup_length == 0) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(sender_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(receiver_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(receiver_public_ephemeral);

	if (conversation != nullptr) {
		conversation_destroy(conversation);
	}

	if (user != nullptr) {
		sodium_mprotect_noaccess(user->master_keys);
	}

	on_error {
		if (packet_buffer != nullptr) {
			//not using free_and_null_if_valid because content is const
			free(packet_buffer->content);
		}
	}

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
		//optional output (can be nullptr)
		unsigned char ** const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t * const backup_length
		) {

	return_status status = return_status_init();

	//create buffers to wrap the raw arrays
	Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
	Buffer packet_buffer(packet, packet_length);
	Buffer sender_public_master_key_buffer(sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer receiver_public_master_key_buffer(receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);

	conversation_t *conversation = nullptr;
	Buffer *message_buffer = nullptr;
	user_store_node *user = nullptr;

	if ((conversation_id == nullptr)
		|| (message == nullptr) || (message_length == nullptr)
		|| (packet == nullptr)
		|| (prekey_list == nullptr) || (prekey_list_length == nullptr)
		|| (sender_public_master_key == nullptr)
		|| (receiver_public_master_key == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_start_receive_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

	if (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Senders public master key has an incorrect size.");
	}

	if (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Receivers public master key has an incorrect size.");
	}

	//get the user that matches the public signing key of the receiver
	status = user_store_find_node(&user, users, &receiver_public_master_key_buffer);
	THROW_on_error(NOT_FOUND, "User not found in the user store.");

	//unlock the master keys
	sodium_mprotect_readonly(user->master_keys);

	//create the conversation
	status = conversation_start_receive_conversation(
			&conversation,
			&packet_buffer,
			&message_buffer,
			&user->master_keys->public_identity_key,
			&user->master_keys->private_identity_key,
			user->prekeys);
	THROW_on_error(CREATION_ERROR, "Failed to start receive conversation.");

	//copy the conversation id
	{
		int status_int = conversation_id_buffer.cloneFrom(&conversation->id);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to clone conversation id.");
		}
	}

	//create the prekey list
	status = create_prekey_list(
			&receiver_public_master_key_buffer,
			prekey_list,
			prekey_list_length);
	THROW_on_error(CREATION_ERROR, "Failed to create prekey list.");

	//add the conversation to the conversation store
	status = user->conversations->add(conversation);
	THROW_on_error(ADDITION_ERROR, "Failed to add conversation to the users conversation store.");
	conversation = nullptr;

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;

	if (backup != nullptr) {
		if (backup_length == 0) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	on_error {
		if (message_buffer != nullptr) {
			free(message_buffer->content);
		}
	}

	free_and_null_if_valid(message_buffer);

	if (conversation != nullptr) {
		conversation_destroy(conversation);
	}

	if (user != nullptr) {
		sodium_mprotect_noaccess(user->master_keys);
	}

	return status;
}

/*
 * Find a conversation based on it's conversation id.
 */
static return_status find_conversation(
		conversation_t ** const conversation, //output
		const unsigned char * const conversation_id,
		ConversationStore ** const conversations, //optional, can be nullptr, the conversation store where the conversation is in
		user_store_node ** const user //optional, can be nullptr, the user that the conversation belongs to
		) {
	return_status status = return_status_init();

	conversation_t *conversation_node = nullptr;

	if ((conversation == nullptr) || (conversation_id == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input for find_conversation.");
	}

	//go through all the users
	{
		Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
		user_store_node *node = users->head;
		while (node != nullptr) {
			conversation_node = node->conversations->findNode(conversation_id_buffer);
			if (conversation_node != nullptr) {
				//found the conversation we're searching for
				break;
			}
			user_store_node *next = node->next;
			node = next;
		}

		if (conversation_node == nullptr) {
			goto cleanup;
		}

		//return the containing user
		if ((user != nullptr) && (node != nullptr)) {
			*user = node;
		}

		if (conversations != nullptr) {
			*conversations = node->conversations;
		}
	}

cleanup:
	if (status.status != SUCCESS) {
		if (conversation != nullptr) {
			*conversation = nullptr;
		}
	} else {
		if (conversation != nullptr) { /* clang analyzer was complaining *shrug* */
			*conversation = conversation_node;
		}
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
		//optional output (can be nullptr)
		unsigned char ** const conversation_backup, //exports the conversation, free after use, check if nullptr before use!
		size_t * const conversation_backup_length
		) {

	//create buffer for message array
	Buffer message_buffer(message, message_length);

	Buffer *packet_buffer = nullptr;
	conversation_t *conversation = nullptr;

	return_status status = return_status_init();

	if ((packet == nullptr) || (packet_length == nullptr)
		|| (message == nullptr)
		|| (conversation_id == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_encrypt_message.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

	//find the conversation
	status = find_conversation(&conversation, conversation_id, nullptr, nullptr);
	THROW_on_error(GENERIC_ERROR, "Error while searching for conversation.");
	if (conversation == nullptr) {
		THROW(NOT_FOUND, "Failed to find a conversation for the given ID.");
	}

	status = conversation_send(
			conversation,
			&message_buffer,
			&packet_buffer,
			nullptr,
			nullptr,
			nullptr);
	THROW_on_error(GENERIC_ERROR, "Failed to send message.");

	*packet = packet_buffer->content;
	*packet_length = packet_buffer->content_length;

	if (conversation_backup != nullptr) {
		if (conversation_backup_length == 0) {
			*conversation_backup = nullptr;
		} else {
			status = molch_conversation_export(conversation_backup, conversation_backup_length, conversation->id.content, conversation->id.content_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export conversation as protocol buffer.");
		}
	}

cleanup:
	on_error {
		if (packet_buffer != nullptr) {
			// not using free_and_null_if_valid because content is const
			free(packet_buffer->content);
		}
	}

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
		//optional output (can be nullptr)
		unsigned char ** const conversation_backup, //exports the conversation, free after use, check if nullptr before use!
		size_t * const conversation_backup_length
	) {
	//create buffer for the packet
	Buffer packet_buffer(packet, packet_length);

	return_status status = return_status_init();

	Buffer *message_buffer = nullptr;
	conversation_t *conversation = nullptr;

	if ((message == nullptr) || (message_length == nullptr)
		|| (packet == nullptr)
		|| (conversation_id == nullptr)
		|| (receive_message_number == nullptr)
		|| (previous_receive_message_number == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_decrypt_message.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

	//find the conversation
	status = find_conversation(&conversation, conversation_id, nullptr, nullptr);
	THROW_on_error(GENERIC_ERROR, "Error while searching for conversation.");
	if (conversation == nullptr) {
		THROW(NOT_FOUND, "Failed to find conversation with the given ID.");
	}

	status = conversation_receive(
			conversation,
			&packet_buffer,
			receive_message_number,
			previous_receive_message_number,
			&message_buffer);
	THROW_on_error(GENERIC_ERROR, "Failed to receive message.");

	*message = message_buffer->content;
	*message_length = message_buffer->content_length;

	if (conversation_backup != nullptr) {
		if (conversation_backup_length == 0) {
			*conversation_backup = nullptr;
		} else {
			status = molch_conversation_export(conversation_backup, conversation_backup_length, conversation->id.content, conversation->id.content_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export conversation as protocol buffer.");
		}
	}

cleanup:
	on_error {
		if (message_buffer != nullptr) {
			// not using free_and_null_if_valid because content is const
			free(message_buffer->content);
		}
	}

	free_and_null_if_valid(message_buffer);

	return status;
}

return_status molch_end_conversation(
		//input
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		//optional output (can be nullptr)
		unsigned char ** const backup,
		size_t * const backup_length
		) {
	return_status status = return_status_init();

	if (conversation_id == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to molch_end_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect length.");
	}

	//find the conversation
	{
		conversation_t *conversation = nullptr;
		user_store_node *user = nullptr;
		status = find_conversation(&conversation, conversation_id, nullptr, &user);
		THROW_on_error(NOT_FOUND, "Couldn't find converstion.");

		if (conversation == nullptr) {
			THROW(NOT_FOUND, "Couldn'nt find conversation.");
		}

		user->conversations->removeById(conversation->id);
	}

	if (backup != nullptr) {
		if (backup_length == 0) {
			*backup = nullptr;
		} else {
			return_status local_status = molch_export(backup, backup_length);
			if (local_status.status != SUCCESS) {
				*backup = nullptr;
			}
		}
	}

cleanup:

	return status;
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
	Buffer user_public_master_key_buffer(user_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer *conversation_list_buffer = nullptr;

	return_status status = return_status_init();

	if ((user_public_master_key == nullptr) || (conversation_list == nullptr) || (conversation_list_length == nullptr) || (number == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_list_conversations.");
	}

	if (user_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has an incorrect length.");
	}

	*conversation_list = nullptr;

	{
		user_store_node *user = nullptr;
		status = user_store_find_node(&user, users, &user_public_master_key_buffer);
		THROW_on_error(NOT_FOUND, "No user found for the given public identity.")

		status = user->conversations->list(conversation_list_buffer);
		on_error {
			THROW(DATA_FETCH_ERROR, "Failed to list conversations.");
		}
		if (conversation_list_buffer == nullptr) {
			// list is empty
			*conversation_list = nullptr;
			*number = 0;
			goto cleanup;
		}
	}

	if ((conversation_list_buffer->content_length % CONVERSATION_ID_SIZE) != 0) {
		THROW(INCORRECT_BUFFER_SIZE, "The conversation ID buffer has an incorrect length.");
	}
	*number = conversation_list_buffer->content_length / CONVERSATION_ID_SIZE;

	*conversation_list = conversation_list_buffer->content;
	*conversation_list_length = conversation_list_buffer->content_length;
	free(conversation_list_buffer); //free Buffer struct
	conversation_list_buffer = nullptr;

cleanup:
	on_error {
		if (number != nullptr) {
			*number = 0;
		}

		buffer_destroy_from_heap_and_null_if_valid(conversation_list_buffer);
	}

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

	Buffer *conversation_buffer = nullptr;
	Buffer *backup_nonce = nullptr;
	Buffer *backup_buffer = nullptr;

	size_t conversation_size;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	Conversation *conversation_struct = nullptr;

	//check input
	if ((backup == nullptr) || (backup_length == nullptr)
			|| (conversation_id == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_conversation_export");
	}
	if ((conversation_id_length != CONVERSATION_ID_SIZE)) {
		THROW(INVALID_INPUT, "Conversation ID has an invalid size.");
	}

	if ((global_backup_key == nullptr) || (global_backup_key->content_length != BACKUP_KEY_SIZE)) {
		THROW(INCORRECT_DATA, "No backup key found.");
	}

	//find the conversation
	{
		conversation_t *conversation = nullptr;
		status = find_conversation(&conversation, conversation_id, nullptr, nullptr);
		THROW_on_error(NOT_FOUND, "Failed to find the conversation.");

		//export the conversation
		status = conversation_export(conversation, &conversation_struct);
		conversation = nullptr; //remove alias
		THROW_on_error(EXPORT_ERROR, "Failed to export conversation to protobuf-c struct.");
	}

	//pack the struct
	conversation_size = conversation__get_packed_size(conversation_struct);
	conversation_buffer = Buffer::createWithCustomAllocator(conversation_size, 0, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(conversation_buffer);

	conversation_buffer->content_length = conversation__pack(conversation_struct, conversation_buffer->content);
	if (conversation_buffer->content_length != conversation_size) {
		THROW(PROTOBUF_PACK_ERROR, "Failed to pack conversation to protobuf-c.");
	}

	//generate the nonce
	backup_nonce = Buffer::create(BACKUP_NONCE_SIZE, 0);
	THROW_on_failed_alloc(backup_nonce);
	if (backup_nonce->fillRandom(BACKUP_NONCE_SIZE) != 0) {
		THROW(GENERIC_ERROR, "Failed to generaete backup nonce.");
	}

	//allocate the output
	backup_buffer = Buffer::create(conversation_size + crypto_secretbox_MACBYTES, conversation_size + crypto_secretbox_MACBYTES);
	THROW_on_failed_alloc(backup_buffer);

	//encrypt the backup
	{
		int status_int = crypto_secretbox_easy(
				backup_buffer->content,
				conversation_buffer->content,
				conversation_buffer->content_length,
				backup_nonce->content,
				global_backup_key->content);
		if (status_int != 0) {
			backup_buffer->content_length = 0;
			THROW(ENCRYPT_ERROR, "Failed to enrypt conversation state.");
		}
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
	{
		const size_t encrypted_backup_size = encrypted_backup__get_packed_size(&encrypted_backup_struct);
		*backup = (unsigned char*)malloc(encrypted_backup_size);
		*backup_length = encrypted_backup__pack(&encrypted_backup_struct, *backup);
		if (*backup_length != encrypted_backup_size) {
			THROW(PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
		}
	}

cleanup:
	on_error {
		if ((backup != nullptr) && (*backup != nullptr)) {
			free(*backup);
			*backup = nullptr;
		}
		if (backup_length != nullptr) {
			*backup_length = 0;
		}
	}

	if (conversation_struct != nullptr) {
		conversation__free_unpacked(conversation_struct, &protobuf_c_allocators);
		conversation_struct = nullptr;
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
		const unsigned char * backup_key,
		const size_t backup_key_length) {
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = nullptr;
	Buffer *decrypted_backup = nullptr;
	Conversation *conversation_struct = nullptr;
	conversation_t *conversation = nullptr;
	ConversationStore *containing_store = nullptr;
	conversation_t *existing_conversation = nullptr;

	//check input
	if ((backup == nullptr) || (backup_key == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_import.");
	}
	if (backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Backup key has an incorrect length.");
	}
	if (new_backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "New backup key has an incorrect length.");
	}

	//unpack the encrypted backup
	encrypted_backup_struct = encrypted_backup__unpack(&protobuf_c_allocators, backup_length, backup);
	if (encrypted_backup_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		THROW(INCORRECT_DATA, "Incompatible backup.");
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
		THROW(INCORRECT_DATA, "Backup is not a conversation backup.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
	}

	decrypted_backup = Buffer::createWithCustomAllocator(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(decrypted_backup);

	//decrypt the backup
	{
		int status_int = crypto_secretbox_open_easy(
				decrypted_backup->content,
				encrypted_backup_struct->encrypted_backup.data,
				encrypted_backup_struct->encrypted_backup.len,
				encrypted_backup_struct->encrypted_backup_nonce.data,
				backup_key);
		if (status_int != 0) {
			THROW(DECRYPT_ERROR, "Failed to decrypt conversation backup.");
		}
	}

	//unpack the struct
	conversation_struct = conversation__unpack(&protobuf_c_allocators, decrypted_backup->content_length, decrypted_backup->content);
	if (conversation_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversations protobuf-c.");
	}

	//import the conversation
	status = conversation_import(&conversation, conversation_struct);
	THROW_on_error(IMPORT_ERROR, "Failed to import conversation from Protobuf-C struct.");

	status = find_conversation(&existing_conversation, conversation->id.content, &containing_store, nullptr);
	THROW_on_error(NOT_FOUND, "Imported conversation has to exist, but it doesn't.");
	if (containing_store == nullptr) {
		THROW(NOT_FOUND, "Containing store not found.");
	}

	status = containing_store->add(conversation);
	THROW_on_error(ADDITION_ERROR, "Failed to add imported conversation to the conversation store.");
	conversation = nullptr;


	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	on_error {
		//remove the new imported conversation
		containing_store->remove(conversation);
		THROW(KEYGENERATION_FAILED, "Failed to update backup key.");
	}

	//everything worked, the old conversation can now be removed
	containing_store->remove(existing_conversation);

cleanup:
	if (encrypted_backup_struct != nullptr) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = nullptr;
	}
	if (conversation_struct != nullptr) {
		conversation__free_unpacked(conversation_struct, &protobuf_c_allocators);
		conversation_struct = nullptr;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(decrypted_backup, zeroed_free);
	if (conversation != nullptr) {
		conversation_destroy(conversation);
		conversation = nullptr;
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

	Buffer *users_buffer = nullptr;
	Buffer *backup_nonce = nullptr;
	Buffer *backup_buffer = nullptr;
	size_t backup_struct_size;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	Backup *backup_struct = nullptr;

	//check input
	if ((backup == nullptr) || (backup_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_export");
	}

	if ((global_backup_key == nullptr) || (global_backup_key->content_length != BACKUP_KEY_SIZE)) {
		THROW(INCORRECT_DATA, "No backup key found.");
	}

	backup_struct = (Backup*)zeroed_malloc(sizeof(Backup));
	THROW_on_failed_alloc(backup_struct);
	backup__init(backup_struct);

	//export the conversation
	status = user_store_export(users, &(backup_struct->users), &(backup_struct->n_users));
	THROW_on_error(EXPORT_ERROR, "Failed to export user store to protobuf-c struct.");

	//pack the struct
	backup_struct_size = backup__get_packed_size(backup_struct);
	users_buffer = Buffer::createWithCustomAllocator(backup_struct_size, 0, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(users_buffer);

	users_buffer->content_length = backup__pack(backup_struct, users_buffer->content);
	if (users_buffer->content_length != backup_struct_size) {
		THROW(PROTOBUF_PACK_ERROR, "Failed to pack conversation to protobuf-c.");
	}

	//generate the nonce
	backup_nonce = Buffer::create(BACKUP_NONCE_SIZE, 0);
	THROW_on_failed_alloc(backup_nonce);
	if (backup_nonce->fillRandom(BACKUP_NONCE_SIZE) != 0) {
		THROW(GENERIC_ERROR, "Failed to generaete backup nonce.");
	}

	//allocate the output
	backup_buffer = Buffer::create(backup_struct_size + crypto_secretbox_MACBYTES, backup_struct_size + crypto_secretbox_MACBYTES);
	THROW_on_failed_alloc(backup_buffer);

	//encrypt the backup
	{
		int status_int = crypto_secretbox_easy(
				backup_buffer->content,
				users_buffer->content,
				users_buffer->content_length,
				backup_nonce->content,
				global_backup_key->content);
		if (status_int != 0) {
			backup_buffer->content_length = 0;
			THROW(ENCRYPT_ERROR, "Failed to enrypt conversation state.");
		}
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
	{
		const size_t encrypted_backup_size = encrypted_backup__get_packed_size(&encrypted_backup_struct);
		*backup = (unsigned char*)malloc(encrypted_backup_size);
		*backup_length = encrypted_backup__pack(&encrypted_backup_struct, *backup);
		if (*backup_length != encrypted_backup_size) {
			THROW(PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
		}
	}

cleanup:
	on_error {
		if ((backup != nullptr) && (*backup != nullptr)) {
			free(*backup);
			*backup = nullptr;
		}
		if (backup_length != nullptr) {
			*backup_length = 0;
		}
	}

	if (backup_struct != nullptr) {
		backup__free_unpacked(backup_struct, &protobuf_c_allocators);
		backup_struct = nullptr;
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
		const unsigned char * const backup_key, //BACKUP_KEY_SIZE
		const size_t backup_key_length
		) {
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = nullptr;
	Buffer *decrypted_backup = nullptr;
	Backup *backup_struct = nullptr;
	user_store *store = nullptr;

	//check input
	if ((backup == nullptr) || (backup_key == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_import.");
	}
	if (backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Backup key has an incorrect length.");
	}
	if (new_backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "New backup key has an incorrect length.");
	}

	if (users == nullptr) {
		if (sodium_init() == -1) {
			THROW(INIT_ERROR, "Failed to init libsodium.");
		}
	}

	//unpack the encrypted backup
	encrypted_backup_struct = encrypted_backup__unpack(&protobuf_c_allocators, backup_length, backup);
	if (encrypted_backup_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		THROW(INCORRECT_DATA, "Incompatible backup.");
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
		THROW(INCORRECT_DATA, "Backup is not a full backup.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted state.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
	}

	decrypted_backup = Buffer::createWithCustomAllocator(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(decrypted_backup);

	//decrypt the backup
	{
		int status_int = crypto_secretbox_open_easy(
				decrypted_backup->content,
				encrypted_backup_struct->encrypted_backup.data,
				encrypted_backup_struct->encrypted_backup.len,
				encrypted_backup_struct->encrypted_backup_nonce.data,
				backup_key);
		if (status_int != 0) {
			THROW(DECRYPT_ERROR, "Failed to decrypt backup.");
		}
	}

	//unpack the struct
	backup_struct = backup__unpack(&protobuf_c_allocators, decrypted_backup->content_length, decrypted_backup->content);
	if (backup_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack backups protobuf-c.");
	}

	//import the user store
	status = user_store_import(&store, backup_struct->users, backup_struct->n_users);
	THROW_on_error(IMPORT_ERROR, "Failed to import user store from Protobuf-C struct.");

	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//everyting worked, switch to the new user store
	user_store_destroy(users);
	users = store;
	store = nullptr;

cleanup:
	if (encrypted_backup_struct != nullptr) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = nullptr;
	}
	if (backup_struct != nullptr) {
		backup__free_unpacked(backup_struct, &protobuf_c_allocators);
		backup_struct = nullptr;
	}
	buffer_destroy_with_custom_deallocator_and_null_if_valid(decrypted_backup, zeroed_free);
	if (store != nullptr) {
		user_store_destroy(store);
		store = nullptr;
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
	if ((public_master_key == nullptr) || (prekey_list == nullptr) || (prekey_list_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_get_prekey_list.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has an incorrect length.");
	}

	{
		Buffer public_signing_key_buffer(public_master_key, PUBLIC_MASTER_KEY_SIZE);

		status = create_prekey_list(
				&public_signing_key_buffer,
				prekey_list,
				prekey_list_length);
		THROW_on_error(CREATION_ERROR, "Failed to create prekey list.");
	}

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

	Buffer new_key_buffer(new_key, BACKUP_KEY_SIZE);

	if (users == nullptr) {
		if (sodium_init() == -1) {
			THROW(INIT_ERROR, "Failed to initialize libsodium.");
		}
	}

	if (new_key == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to molch_update_backup_key.");
	}

	if (new_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "New key has an incorrect length.");
	}

	// create a backup key buffer if it doesnt exist already
	if (global_backup_key == nullptr) {
		global_backup_key = Buffer::createWithCustomAllocator(BACKUP_KEY_SIZE, 0, sodium_malloc, sodium_free);
		THROW_on_failed_alloc(global_backup_key);
	}

	//make backup key buffer writable
	if (sodium_mprotect_readwrite(global_backup_key) != 0) {
		THROW(GENERIC_ERROR, "Failed to make backup key readwrite.");
	}
	//make the content of the backup key writable
	if (sodium_mprotect_readwrite(global_backup_key->content) != 0) {
		THROW(GENERIC_ERROR, "Failed to make backup key content readwrite.");
	}

	if (global_backup_key->fillRandom(BACKUP_KEY_SIZE) != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate new backup key.");
	}

	if (new_key_buffer.cloneFrom(global_backup_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy new backup key.");
	}

cleanup:
	if (global_backup_key != nullptr) {
		sodium_mprotect_readonly(global_backup_key);
		sodium_mprotect_readonly(global_backup_key->content);
	}

	return status;
}
