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

#include <cstdint>
#include <memory>
#include <iostream>

#include "constants.h"
#include "molch.h"
#include "packet.hpp"
#include "buffer.hpp"
#include "user-store.hpp"
#include "endianness.hpp"
#include "zeroed_malloc.hpp"
#include "destroyers.hpp"

extern "C" {
	#include <encrypted_backup.pb-c.h>
	#include <backup.pb-c.h>
}

//global user store
static std::unique_ptr<UserStore> users;
static Buffer *global_backup_key = nullptr;

/*
 * Create a prekey list.
 */
static return_status create_prekey_list(
		Buffer * const public_signing_key,
		unsigned char ** const prekey_list, //output, needs to be freed
		size_t * const prekey_list_length) {

	std::cout << "create_prekey_list" << std::endl;
	return_status status = return_status_init();
	UserStoreNode *user = nullptr;

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
		try {
			user = users->find(*public_signing_key);

			//rotate the prekeys
			user->prekeys.rotate();

			//get the public identity key
			user->master_keys.getIdentityKey(*public_identity_key);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//copy the public identity to the prekey list
		if (unsigned_prekey_list->copyFrom(0, public_identity_key, 0, PUBLIC_KEY_SIZE) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public identity to prekey list.");
		}

		//get the prekeys
		try {
			user->prekeys.list(prekeys);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
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
	try {
		user->master_keys.sign(*unsigned_prekey_list, *prekey_list_buffer);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	*prekey_list = prekey_list_buffer->content;
	*prekey_list_length = prekey_list_buffer->content_length;

cleanup:
	on_error {
		if (prekey_list_buffer != nullptr) {
			free(prekey_list_buffer->content);
		}
	}

	buffer_destroy_and_null_if_valid(public_identity_key);
	buffer_destroy_and_null_if_valid(unsigned_prekey_list);
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
	std::cout << "molch_create_user" << std::endl;
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

	//initialise libsodium and create user store
	if (!users) {
		if (sodium_init() == -1) {
			THROW(INIT_ERROR, "Failed to init libsodium.");
		}
		try {
			users = std::make_unique<UserStore>();
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

	//create a new backup key
	status = molch_update_backup_key(backup_key, backup_key_length);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//create the user
	try {
		if (random_data_length != 0) {
			users->add(UserStoreNode(random_data_buffer, &public_master_key_buffer, nullptr));
		} else {
			users->add(UserStoreNode(&public_master_key_buffer, nullptr));
		}
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	user_store_created = true;

	status = create_prekey_list(
			&public_master_key_buffer,
			prekey_list,
			prekey_list_length);
	THROW_on_error(CREATION_ERROR, "Failed to create prekey list.");

	if (backup != nullptr) {
		if (backup_length == nullptr) {
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
	std::cout << "molch_destroy_user" << std::endl;
	return_status status = return_status_init();

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialised yet.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has incorrect size.");
	}

	//TODO maybe check beforehand if the user exists and return nonzero if not

	{
		Buffer public_signing_key_buffer(public_master_key, PUBLIC_MASTER_KEY_SIZE);
		try {
			users->remove(public_signing_key_buffer);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

	if (backup != nullptr) {
		if (backup_length == nullptr) {
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
	if (!users) {
		return 0;
	}

	return users->size();
}

/*
 * Delete all users.
 */
void molch_destroy_all_users() {
	if (users) {
		users->clear();
	}
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
	std::cout << "molch_list_users" << std::endl;
	return_status status = return_status_init();

	if (!users || (user_list_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_list_users.");
	}

	//get the list of users and copy it
	{
		std::unique_ptr<Buffer> list;
		try {
			list = users->list();
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		*count = molch_user_count();

		if (*count == 0) {
			*user_list = nullptr;
		} else {
			*user_list = reinterpret_cast<unsigned char*>(malloc(*count * PUBLIC_MASTER_KEY_SIZE));
			THROW_on_failed_alloc(*user_list);
			std::copy(list->content, list->content + list->content_length, *user_list);
		}

		*user_list_length = list->content_length;
	}

cleanup:
	on_error {
		if (user_list != nullptr) {
			free_and_null_if_valid(*user_list);
		}

		*count = 0;
	}
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
	try {
		packet_get_metadata_without_verification(
			current_protocol_version,
			highest_supported_protocol_version,
			packet_type,
			packet_buffer,
			nullptr,
			nullptr,
			nullptr);
	} catch (const std::exception& exception) {
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
	std::cout << "verify_prekey_list" << std::endl;
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
				static_cast<unsigned long long>(prekey_list_length),
				public_signing_key->content);
		if (status_int != 0) {
			THROW(VERIFICATION_FAILED, "Failed to verify prekey list signature.");
		}
		if (verified_length > SIZE_MAX)
		{
			THROW(CONVERSION_ERROR, "Length is bigger than size_t.");
		}
		verified_prekey_list->content_length = static_cast<size_t>(verified_length);
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
	buffer_destroy_and_null_if_valid(verified_prekey_list);

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
	std::cout << "molch_start_send_conversation" << std::endl;
	//create buffers wrapping the raw input
	Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
	Buffer message_buffer(message, message_length);
	Buffer sender_public_master_key_buffer(sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer receiver_public_master_key_buffer(receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer prekeys(prekey_list + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t));

	ConversationT *conversation = nullptr;
	std::unique_ptr<Buffer> packet_buffer;
	UserStoreNode *user = nullptr;

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

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialised yet.");
	}

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
	try {
		user = users->find(sender_public_master_key_buffer);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}
	if (user == nullptr) {
		THROW(NOT_FOUND, "User not found.");
	}

	//get the receivers public ephemeral and identity
	status = verify_prekey_list(
			prekey_list,
			prekey_list_length,
			receiver_public_identity,
			&receiver_public_master_key_buffer);
	THROW_on_error(VERIFICATION_FAILED, "Failed to verify prekey list.");

	//unlock the master keys
	try {
		MasterKeys::Unlocker unlocker(user->master_keys);

		//create the conversation and encrypt the message
		conversation = new ConversationT(
				message_buffer,
				packet_buffer,
				user->master_keys.public_identity_key,
				user->master_keys.private_identity_key,
				*receiver_public_identity,
				prekeys);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the conversation id
	{
		int status_int = conversation_id_buffer.cloneFrom(&conversation->id);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to clone conversation id.");
		}
	}

	try {
		user->conversations.add(std::move(*conversation));
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the packet to the output
	*packet = reinterpret_cast<unsigned char*>(malloc(packet_buffer->content_length));
	THROW_on_failed_alloc(*packet);
	if (packet_buffer->cloneToRaw(*packet, packet_buffer->content_length) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy packet from unique_ptr.");
	}
	*packet_length = packet_buffer->content_length;

	if (backup != nullptr) {
		if (backup_length == nullptr) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	buffer_destroy_and_null_if_valid(sender_public_identity);
	buffer_destroy_and_null_if_valid(receiver_public_identity);
	buffer_destroy_and_null_if_valid(receiver_public_ephemeral);

	delete conversation;

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
	std::cout << "molch_start_receive_conversation" << std::endl;

	return_status status = return_status_init();

	//create buffers to wrap the raw arrays
	Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
	Buffer packet_buffer(packet, packet_length);
	Buffer sender_public_master_key_buffer(sender_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	Buffer receiver_public_master_key_buffer(receiver_public_master_key, PUBLIC_MASTER_KEY_SIZE);

	ConversationT *conversation = nullptr;
	std::unique_ptr<Buffer> message_buffer;
	UserStoreNode *user = nullptr;

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

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
	try {
		user = users->find(receiver_public_master_key_buffer);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}
	if (user == nullptr) {
		THROW(NOT_FOUND, "User not found in the user store.");
	}

	//unlock the master keys
	try {
		MasterKeys::Unlocker unlocker(user->master_keys);

		//create the conversation
		conversation = new ConversationT(
				packet_buffer,
				message_buffer,
				user->master_keys.public_identity_key,
				user->master_keys.private_identity_key,
				user->prekeys);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

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
	try {
		user->conversations.add(std::move(*conversation));
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the message
	*message = reinterpret_cast<unsigned char*>(malloc(message_buffer->content_length));
	if (message_buffer->cloneToRaw(*message, message_buffer->content_length) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy message from unique_ptr.");
	}
	*message_length = message_buffer->content_length;

	if (backup != nullptr) {
		if (backup_length == nullptr) {
			*backup = nullptr;
		} else {
			status = molch_export(backup, backup_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export.");
		}
	}

cleanup:
	delete conversation;

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
	std::cout << "molch_encrypt_message" << std::endl;

	//create buffer for message array
	Buffer message_buffer(message, message_length);

	std::unique_ptr<Buffer> packet_buffer;
	ConversationT *conversation = nullptr;

	return_status status = return_status_init();

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

	if ((packet == nullptr) || (packet_length == nullptr)
		|| (message == nullptr)
		|| (conversation_id == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_encrypt_message.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect size.");
	}

	//find the conversation
	try {
		Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
		UserStoreNode *user;
		conversation = users->findConversation(user, conversation_id_buffer);
		if (conversation == nullptr) {
			throw MolchException(NOT_FOUND, "Failed to find a conversation for the given ID.");
		}

		packet_buffer = conversation->send(
				message_buffer,
				nullptr,
				nullptr,
				nullptr);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the packet content
	*packet = reinterpret_cast<unsigned char*>(malloc(packet_buffer->content_length));
	THROW_on_failed_alloc(*packet);
	if (packet_buffer->cloneToRaw(*packet, packet_buffer->content_length) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy packet from unique_ptr.");
	}
	*packet_length = packet_buffer->content_length;

	if (conversation_backup != nullptr) {
		if (conversation_backup_length == nullptr) {
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
	std::cout << "molch_decrypt_message" << std::endl;
	//create buffer for the packet
	Buffer packet_buffer(packet, packet_length);

	return_status status = return_status_init();

	std::unique_ptr<Buffer> message_buffer;
	ConversationT *conversation = nullptr;

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

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
	try {
		Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
		UserStoreNode* user;
		conversation = users->findConversation(user, conversation_id_buffer);
		if (conversation == nullptr) {
			throw MolchException(NOT_FOUND, "Failed to find conversation with the given ID.");
		}

		message_buffer = conversation->receive(
				packet_buffer,
				*receive_message_number,
				*previous_receive_message_number);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the message
	*message = reinterpret_cast<unsigned char*>(malloc(message_buffer->content_length));
	if (message_buffer->cloneToRaw(*message, message_buffer->content_length) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy message from unique_ptr.");
	}
	*message_length = message_buffer->content_length;

	if (conversation_backup != nullptr) {
		if (conversation_backup_length == nullptr) {
			*conversation_backup = nullptr;
		} else {
			status = molch_conversation_export(conversation_backup, conversation_backup_length, conversation->id.content, conversation->id.content_length);
			THROW_on_error(EXPORT_ERROR, "Failed to export conversation as protocol buffer.");
		}
	}

cleanup:
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
	std::cout << "molch_end_conversation" << std::endl;
	return_status status = return_status_init();

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

	if (conversation_id == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to molch_end_conversation.");
	}

	if (conversation_id_length != CONVERSATION_ID_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Conversation ID has an incorrect length.");
	}

	//find the conversation
	{
		UserStoreNode *user = nullptr;
		Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
		try {
			ConversationT *conversation = nullptr;
			conversation = users->findConversation(user, conversation_id_buffer);
			if (conversation == nullptr) {
				throw MolchException(NOT_FOUND, "Couldn't find conversation.");
			}

			user->conversations.remove(conversation_id_buffer);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

	if (backup != nullptr) {
		if (backup_length == nullptr) {
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
	std::cout << "molch_list_conversations" << std::endl;
	Buffer user_public_master_key_buffer(user_public_master_key, PUBLIC_MASTER_KEY_SIZE);
	std::unique_ptr<Buffer> conversation_list_buffer = nullptr;

	return_status status = return_status_init();

	if (conversation_list != nullptr) {
		*conversation_list = nullptr;
	}

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

	if ((user_public_master_key == nullptr) || (conversation_list == nullptr) || (conversation_list_length == nullptr) || (number == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_list_conversations.");
	}

	if (user_public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		std::cout << "molch_list_conversations: user_public_master_key_length = " << user_public_master_key_length << std::endl;
		THROW(INCORRECT_BUFFER_SIZE, "Public master key has an incorrect length.");
	}

	{
		UserStoreNode *user = nullptr;
		try {
			user = users->find(user_public_master_key_buffer);
			if (user == nullptr) {
				throw MolchException(NOT_FOUND, "No user found for the given public identity.");
			}

			conversation_list_buffer = user->conversations.list();
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
		on_error {
			THROW(DATA_FETCH_ERROR, "Failed to list conversations.");
		}
		if (!conversation_list_buffer) {
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

	//allocate the conversation list output and copy it over
	*conversation_list = reinterpret_cast<unsigned char*>(malloc(conversation_list_buffer->content_length));
	THROW_on_failed_alloc(*conversation_list);
	std::copy(conversation_list_buffer->content, conversation_list_buffer->content + conversation_list_buffer->content_length, *conversation_list);
	*conversation_list_length = conversation_list_buffer->content_length;

cleanup:
	on_error {
		if (number != nullptr) {
			*number = 0;
		}

		if (conversation_list != nullptr) {
			free_and_null_if_valid(*conversation_list);
		}
		if (conversation_list_length != nullptr) {
			*conversation_list_length = 0;
		}
	}

	return status;
}

/*
 * Print a return status into a nice looking error message.
 *
 * Don't forget to free the output after use.
 */
char *molch_print_status(size_t * const output_length, return_status status) {
	std::cout << "molch_print_status" << std::endl;
	return return_status_print(&status, output_length);
}

/*
 * Get a string describing the return status type.
 *
 * (return_status.status)
 */
const char *molch_print_status_type(status_type type) {
	std::cout << "molch_print_status_type" << std::endl;
	return return_status_get_name(type);
}

/*
 * Destroy a return status (only needs to be called if there was an error).
 */
void molch_destroy_return_status(return_status * const status) {
	std::cout << "molch_destroy" << std::endl;
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
	std::cout << "molch_conversation_export" << std::endl;
	return_status status = return_status_init();

	Buffer *conversation_buffer = nullptr;
	Buffer *backup_nonce = nullptr;
	Buffer *backup_buffer = nullptr;

	size_t conversation_size;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	std::unique_ptr<Conversation,ConversationDeleter> conversation_struct;

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

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

	{
		try {
			//find the conversation
			ConversationT *conversation = nullptr;
			UserStoreNode *user;
			Buffer conversation_id_buffer(conversation_id, CONVERSATION_ID_SIZE);
			conversation = users->findConversation(user, conversation_id_buffer);
			if (conversation == nullptr) {
				throw MolchException(NOT_FOUND, "Failed to find the conversation.");
			}

			//export the conversation
			conversation_struct = conversation->exportProtobuf();
			conversation = nullptr; //remove alias
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

	//pack the struct
	conversation_size = conversation__get_packed_size(conversation_struct.get());
	conversation_buffer = Buffer::createWithCustomAllocator(conversation_size, 0, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(conversation_buffer);

	conversation_buffer->content_length = conversation__pack(conversation_struct.get(), conversation_buffer->content);
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
		*backup = reinterpret_cast<unsigned char*>(malloc(encrypted_backup_size));
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

	buffer_destroy_and_null_if_valid(conversation_buffer);
	buffer_destroy_and_null_if_valid(backup_nonce);
	buffer_destroy_and_null_if_valid(backup_buffer);

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
	std::cout << "molch_conversation_import" << std::endl;
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = nullptr;
	Buffer *decrypted_backup = nullptr;
	Conversation *conversation_struct = nullptr;

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

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
	try {
		ConversationT conversation(*conversation_struct);
		ConversationT* existing_conversation = nullptr;
		UserStoreNode* containing_user = nullptr;
		Buffer conversation_id_buffer(conversation_struct->id.data, conversation_struct->id.len);
		existing_conversation = users->findConversation(containing_user, conversation_id_buffer);
		if (existing_conversation == nullptr) {
			throw MolchException(NOT_FOUND, "Containing store not found.");
		}

		containing_user->conversations.add(std::move(conversation));
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	on_error {
		THROW(KEYGENERATION_FAILED, "Failed to update backup key.");
	}

cleanup:
	if (encrypted_backup_struct != nullptr) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = nullptr;
	}
	if (conversation_struct != nullptr) {
		conversation__free_unpacked(conversation_struct, &protobuf_c_allocators);
		conversation_struct = nullptr;
	}
	buffer_destroy_and_null_if_valid(decrypted_backup);

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
	std::cout << "molch_export" << std::endl;
	return_status status = return_status_init();

	Buffer *users_buffer = nullptr;
	Buffer *backup_nonce = nullptr;
	Buffer *backup_buffer = nullptr;
	size_t backup_struct_size;

	EncryptedBackup encrypted_backup_struct;
	encrypted_backup__init(&encrypted_backup_struct);
	Backup *backup_struct = nullptr;

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

	//check input
	if ((backup == nullptr) || (backup_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_export");
	}

	if ((global_backup_key == nullptr) || (global_backup_key->content_length != BACKUP_KEY_SIZE)) {
		THROW(INCORRECT_DATA, "No backup key found.");
	}

	backup_struct = reinterpret_cast<Backup*>(zeroed_malloc(sizeof(Backup)));
	THROW_on_failed_alloc(backup_struct);
	backup__init(backup_struct);

	//export the conversation
	try {
		users->exportProtobuf(backup_struct->users, backup_struct->n_users);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

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
		*backup = reinterpret_cast<unsigned char*>(malloc(encrypted_backup_size));
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
	buffer_destroy_and_null_if_valid(users_buffer);
	buffer_destroy_and_null_if_valid(backup_nonce);
	buffer_destroy_and_null_if_valid(backup_buffer);

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
	std::cout << "molch_import" << std::endl;
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = nullptr;
	Buffer *decrypted_backup = nullptr;
	Backup *backup_struct = nullptr;
	std::unique_ptr<UserStore> store;

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

	if (!users) {
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

	try {
		//import the user store
		store = std::make_unique<UserStore>(backup_struct->users, backup_struct->n_users);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//update the backup key
	status = molch_update_backup_key(new_backup_key, new_backup_key_length);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//everyting worked, switch to the new user store
	users.reset(store.release());

cleanup:
	if (encrypted_backup_struct != nullptr) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = nullptr;
	}
	if (backup_struct != nullptr) {
		backup__free_unpacked(backup_struct, &protobuf_c_allocators);
		backup_struct = nullptr;
	}
	buffer_destroy_and_null_if_valid(decrypted_backup);

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
	std::cout << "molch_get_prekey_list" << std::endl;
	return_status status = return_status_init();

	if (!users) {
		THROW(INIT_ERROR, "Molch hasn't been initialized yet.");
	}

	// check input
	if ((public_master_key == nullptr) || (prekey_list == nullptr) || (prekey_list_length == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_get_prekey_list.");
	}

	if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
		std::cout << "molch_get_prekey_list: public_master_key_length = " << public_master_key_length << std::endl;
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
	std::cout << "molch_update_backup_key" << std::endl;
	return_status status = return_status_init();

	Buffer new_key_buffer(new_key, BACKUP_KEY_SIZE);

	if (!users) {
		if (sodium_init() == -1) {
			THROW(INIT_ERROR, "Failed to initialize libsodium.");
		}
		try {
			users = std::make_unique<UserStore>();
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
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
