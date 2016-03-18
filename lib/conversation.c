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

#include "constants.h"
#include "conversation.h"
#include "molch.h"
#include "packet.h"
#include "header.h"

/*
 * Create a new conversation struct and initialise the buffer pointer.
 */
void init_struct(conversation_t *conversation) {
	buffer_init_with_pointer(conversation->id, conversation->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	conversation->ratchet = NULL;
	conversation->previous = NULL;
	conversation->next = NULL;
}

/*
 * Create a new conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_create(
		conversation_t **const conversation,
		const buffer_t * const,
		const buffer_t * const,
		const buffer_t * const,
		const buffer_t * const,
		const buffer_t * const,
		const buffer_t * const) __attribute__((warn_unused_result));
return_status conversation_create(
		conversation_t **const conversation,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {

	return_status status = return_status_init();

	//check input
	if ((conversation == NULL)
			|| (our_private_identity == NULL) || (our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity == NULL) || (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity == NULL) || (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral == NULL) || (our_public_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input for conversation_create.");
	}

	*conversation = malloc(sizeof(conversation_t));
	if (conversation == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate memory for conversation.");
	}

	init_struct(*conversation);

	//create random id
	if (buffer_fill_random((*conversation)->id, CONVERSATION_ID_SIZE) != 0) {
		throw(BUFFER_ERROR, "Failed to create random conversation id.");
	}

	(*conversation)->ratchet = ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if ((*conversation)->ratchet == NULL) {
		throw(CREATION_ERROR, "Failed to create ratchet.");
	}

cleanup:
	if (status.status != 0) {
		if ((conversation != NULL) && (*conversation != NULL)) {
			free(*conversation);
			*conversation = NULL;
		}
	}

	return status;
}

/*
 * Destroy a conversation.
 */
void conversation_destroy(conversation_t * const conversation) {
	if (conversation->ratchet != NULL) {
		ratchet_destroy(conversation->ratchet);
	}
	free(conversation);
}

/*
 * Serialise a conversation into JSON. It get#s a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of failure.
 */
mcJSON *conversation_json_export(const conversation_t * const conversation, mempool_t * const pool) {
	if ((conversation == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	mcJSON *id = mcJSON_CreateHexString(conversation->id, pool);
	if (id == NULL) {
		return NULL;
	}
	mcJSON *ratchet = ratchet_json_export(conversation->ratchet, pool);
	if (ratchet == NULL) {
		return NULL;
	}

	buffer_create_from_string(id_string, "id");
	mcJSON_AddItemToObject(json, id_string, id, pool);
	buffer_create_from_string(ratchet_string, "ratchet");
	mcJSON_AddItemToObject(json, ratchet_string, ratchet, pool);

	return json;
}

/*
 * Deserialize a conversation (import from JSON)
 */
conversation_t *conversation_json_import(const mcJSON * const json) {
	if ((json == NULL) || (json->type != mcJSON_Object)) {
		return NULL;
	}

	conversation_t *conversation = malloc(sizeof(conversation_t));
	if (conversation == NULL) {
		return NULL;
	}
	init_struct(conversation);

	int status = 0;

	//import the json
	buffer_create_from_string(id_string, "id");
	mcJSON *id = mcJSON_GetObjectItem(json, id_string);
	buffer_create_from_string(ratchet_string, "ratchet");
	mcJSON *ratchet = mcJSON_GetObjectItem(json, ratchet_string);
	if ((id == NULL) || (id->type != mcJSON_String) || (id->valuestring->content_length != (2 * CONVERSATION_ID_SIZE + 1))
			|| (ratchet == NULL) || (ratchet->type != mcJSON_Object)) {
		status = -1;
		goto cleanup;
	}

	//copy the id
	if (buffer_clone_from_hex(conversation->id, id->valuestring) != 0) {
		status = -1;
		goto cleanup;
	}

	//import the ratchet state
	conversation->ratchet = ratchet_json_import(ratchet);
	if (conversation->ratchet == NULL) {
		status = -1;
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		if (conversation->ratchet != NULL) {
			ratchet_destroy(conversation->ratchet);
		}

		free(conversation);

		return NULL;
	}

	return conversation;
}

/*
 * Start a new conversation where we are the sender.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_start_send_conversation(
		conversation_t ** const conversation, //output, newly created conversation
		const buffer_t *const message, //message we want to send to the receiver
		buffer_t ** packet, //output, free after use!
		const buffer_t * const sender_public_identity, //who is sending this message?
		const buffer_t * const sender_private_identity,
		const buffer_t * const receiver_public_identity,
		const buffer_t * const receiver_prekey_list //PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		) {

	return_status status = return_status_init();

	buffer_t *sender_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *sender_private_ephemeral = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);

	//check many error conditions
	if ((conversation == NULL)
			|| (message == NULL)
			|| (packet == NULL)
			|| (receiver_public_identity == NULL) || (receiver_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (sender_public_identity == NULL) || (sender_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (sender_private_identity == NULL) || (sender_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (receiver_prekey_list == NULL) || (receiver_prekey_list->content_length != (PREKEY_AMOUNT * PUBLIC_KEY_SIZE))) {
		throw(INVALID_INPUT, "Invalid input to conversation_start_send_conversation.");
	}

	*conversation = NULL;

	int status_int = 0;
	//create an ephemeral keypair
	status_int = crypto_box_keypair(sender_public_ephemeral->content, sender_private_ephemeral->content);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate ephemeral keypair.");
	}

	//choose a prekey
	uint32_t prekey_number = randombytes_uniform(PREKEY_AMOUNT);
	buffer_create_with_existing_array(
			receiver_public_prekey,
			&(receiver_prekey_list->content[prekey_number * PUBLIC_KEY_SIZE]),
			PUBLIC_KEY_SIZE);

	//initialize the conversation
	status = conversation_create(
			conversation,
			sender_private_identity,
			sender_public_identity,
			receiver_public_identity,
			sender_private_ephemeral,
			sender_public_ephemeral,
			receiver_public_prekey);
	throw_on_error(CREATION_ERROR, "Failed to create conversation.");

	status = conversation_send(
			*conversation,
			message,
			packet,
			sender_public_identity,
			sender_public_ephemeral,
			receiver_public_prekey);
	throw_on_error(SEND_ERROR, "Failed to send message using newly created conversation.");

cleanup:
	buffer_destroy_from_heap(sender_public_ephemeral);
	buffer_destroy_from_heap(sender_private_ephemeral);

	if (status.status != SUCCESS) {
		if (conversation != NULL) {
			if (*conversation != NULL) {
				conversation_destroy(*conversation);
			}
			*conversation = NULL;
		}
	}

	return status;
}

/*
 * Start a new conversation where we are the receiver.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_start_receive_conversation(
		conversation_t ** const conversation, //output, newly created conversation
		const buffer_t * const packet, //received packet
		buffer_t ** message, //output, free after use!
		const buffer_t * const receiver_public_identity,
		const buffer_t * const receiver_private_identity,
		prekey_store * const receiver_prekeys //prekeys of the receiver
		) {
	//key buffers
	buffer_t *receiver_public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *receiver_private_prekey = buffer_create_on_heap(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_t *sender_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *sender_public_identity = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	return_status status = return_status_init();

	if ((conversation == NULL)
			|| (packet ==NULL)
			|| (message == NULL)
			|| (receiver_public_identity == NULL) || (receiver_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (receiver_private_identity == NULL) || (receiver_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (receiver_prekeys == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_start_receive_conversation.");
	}

	int status_int = 0;

	*conversation = NULL;

	//get the senders keys and our public prekey from the packet
	unsigned char packet_type;
	unsigned char current_protocol_version;
	unsigned char highest_supported_protocol_version;
	unsigned char header_length;
	status_int = packet_get_metadata_without_verification(
			packet,
			&packet_type,
			&current_protocol_version,
			&highest_supported_protocol_version,
			&header_length,
			sender_public_identity,
			sender_public_ephemeral,
			receiver_public_prekey);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to get packet metadata.");
	}

	if (packet_type != PREKEY_MESSAGE) {
		throw(INVALID_VALUE, "Packet is not a prekey message.");
	}

	//get the private prekey that corresponds to the public prekey used in the message
	status_int = prekey_store_get_prekey(
			receiver_prekeys,
			receiver_public_prekey,
			receiver_private_prekey);
	if (status_int != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get public prekey.");
	}

	status = conversation_create(
			conversation,
			receiver_private_identity,
			receiver_public_identity,
			sender_public_identity,
			receiver_private_prekey,
			receiver_public_prekey,
			sender_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create conversation.");

	status = conversation_receive(
			*conversation,
			packet,
			message);
	throw_on_error(RECEIVE_ERROR, "Failed to receive message.");

cleanup:
	buffer_destroy_from_heap(receiver_public_prekey);
	buffer_destroy_from_heap(receiver_private_prekey);
	buffer_destroy_from_heap(sender_public_ephemeral);
	buffer_destroy_from_heap(sender_public_identity);

	if (status.status != SUCCESS) {
		if (conversation != NULL) {
			if (*conversation != NULL) {
				conversation_destroy(*conversation);
			}
			*conversation = NULL;
		}
	}

	return status;
}

/*
 * Send a message using an existing conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_send(
		conversation_t * const conversation,
		const buffer_t * const message,
		buffer_t **packet, //output, free after use!
		const buffer_t * const public_identity_key, //can be NULL, if not NULL, this will be a prekey message
		const buffer_t * const public_ephemeral_key, //can be NULL, if not NULL, this will be a prekey message
		const buffer_t * const public_prekey //can be NULL, if not NULL, this will be a prekey message
		) {

	//create buffers
	buffer_t *send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *send_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	buffer_t *send_ephemeral_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	buffer_t *header = buffer_create_on_heap(PUBLIC_KEY_SIZE + 8, PUBLIC_KEY_SIZE + 8);

	return_status status = return_status_init();

	//check input
	if ((conversation == NULL)
			|| (message == NULL)
			|| (packet == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_send.");
	}

	//ensure that either both public keys are NULL or set
	if (((public_identity_key == NULL) && (public_prekey != NULL)) || ((public_prekey == NULL) && (public_identity_key != NULL))) {
		throw(INVALID_INPUT, "Invalid combination of provided key buffers.");
	}

	//check the size of the public keys
	if (((public_identity_key != NULL) && (public_identity_key->content_length != PUBLIC_KEY_SIZE)) || ((public_prekey != NULL) && (public_prekey->content_length != PUBLIC_KEY_SIZE))) {
		throw(INCORRECT_BUFFER_SIZE, "Public key output has incorrect size.");
	}

	unsigned char packet_type = NORMAL_MESSAGE;
	//check if this is a prekey message
	if (public_identity_key != NULL) {
		packet_type = PREKEY_MESSAGE;
	}

	int status_int = 0;

	*packet = NULL;

	uint32_t send_message_number;
	uint32_t previous_send_message_number;
	status_int = ratchet_send(
			conversation->ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			send_ephemeral_key,
			send_message_key);
	if (status_int != 0) {
		throw(SEND_ERROR, "Failed to get send keys.");
	}

	//create the header
	status_int = header_construct(
			header,
			send_ephemeral_key,
			send_message_number,
			previous_send_message_number);
	if (status_int != 0) {
		throw(CREATION_ERROR, "Failed to construct header.");
	}

	const size_t packet_length = header->content_length + 3 + HEADER_NONCE_SIZE + MESSAGE_NONCE_SIZE + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_MACBYTES + message->content_length + 255 + (packet_type == PREKEY_MESSAGE) * 3 * PUBLIC_KEY_SIZE;
	*packet = buffer_create_on_heap(packet_length, 0);
	status = packet_encrypt(
			*packet,
			packet_type,
			0, //current protocol version
			0, //highest supported protocol version
			header,
			send_header_key,
			message,
			send_message_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	throw_on_error(ENCRYPT_ERROR, "Failed to encrypt packet.");

cleanup:
	if (status.status != SUCCESS) {
		if (packet != NULL) {
			if (*packet != NULL) {
				buffer_destroy_from_heap(*packet);
			}
			*packet = NULL;
		}
	}
	buffer_destroy_from_heap(send_header_key);
	buffer_destroy_from_heap(send_message_key);
	buffer_destroy_from_heap(send_ephemeral_key);
	buffer_destroy_from_heap(header);

	return status;
}

/*
 * Receive and decrypt a message using an existing conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_receive(
	conversation_t * const conversation,
	const buffer_t * const packet, //received packet
	buffer_t ** const message) { //output, free after use!
	int status_int = 0;

	//create buffers
	buffer_t *current_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *next_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *header = buffer_create_on_heap(255, 255);
	buffer_t *message_nonce = buffer_create_on_heap(MESSAGE_NONCE_SIZE, MESSAGE_NONCE_SIZE);
	buffer_t *their_signed_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);

	return_status status = return_status_init();

	if ((conversation == NULL)
			|| (packet == NULL)
			|| (message == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_receive.");
	}

	*message = buffer_create_on_heap(packet->content_length, 0);

	status_int = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			conversation->ratchet);
	if (status_int != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get receive header keys.");
	}

	//try to decrypt the packet header with the current receive header key
	status = packet_decrypt_header(
			packet,
			header,
			message_nonce,
			current_receive_header_key,
			NULL,
			NULL,
			NULL);
	if (status.status == SUCCESS) {
		status_int = ratchet_set_header_decryptability(
				conversation->ratchet,
				CURRENT_DECRYPTABLE);
		if (status_int != 0) {
			throw(DATA_SET_ERROR, "Failed to set decryptability to CURRENT_DECRYPTABLE.");
		}
	} else {
		return_status_destroy_errors(&status); //free the error stack to avoid memory leak.

		//since this failed, try to decrypt it with the next receive header key
		status = packet_decrypt_header(
				packet,
				header,
				message_nonce,
				next_receive_header_key,
				NULL,
				NULL,
				NULL);
		if (status.status == SUCCESS) {
			status_int = ratchet_set_header_decryptability(
					conversation->ratchet,
					NEXT_DECRYPTABLE);
			if (status_int != 0) {
				throw(DATA_SET_ERROR, "Failed to set decryptability to NEXT_DECRYPTABLE.");
			}
		} else {
			int decryptability_status_int __attribute__((unused)); //tell the static analyser not to complain about this
			decryptability_status_int = ratchet_set_header_decryptability(
					conversation->ratchet,
					UNDECRYPTABLE);
			throw(DECRYPT_ERROR, "Header undecryptable.");
		}
	}

	//extract data from the header
	uint32_t message_counter;
	uint32_t previous_message_counter;
	status_int = header_extract(
			header,
			their_signed_public_ephemeral,
			&message_counter,
			&previous_message_counter);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to extract data from header.");
	}

	//and now decrypt the message with the message key
	//now we have all the data we need to advance the ratchet
	//so let's do that
	status_int = ratchet_receive(
			conversation->ratchet,
			message_key,
			their_signed_public_ephemeral,
			message_counter,
			previous_message_counter);
	if (status_int != 0) {
		throw(DECRYPT_ERROR, "Failed to get decryption keys.");
	}

	status = packet_decrypt_message(
			packet,
			*message,
			message_nonce,
			message_key);
	if (status.status != SUCCESS) {
		int authenticity_status_int __attribute__((unused)); //tell the static analyser to not complain about this
		authenticity_status_int = ratchet_set_last_message_authenticity(conversation->ratchet, false);
		throw(DECRYPT_ERROR, "Failed to decrypt message.");
	}

	status_int = ratchet_set_last_message_authenticity(conversation->ratchet, true);
	if (status_int != 0) {
		throw(DATA_SET_ERROR, "Failed to set message authenticity.");
	}

cleanup:
	if (status.status != SUCCESS) {
		int authenticity_status __attribute__((unused)); //tell the static analyser to not complain about this
		if (conversation != NULL) {
			authenticity_status = ratchet_set_last_message_authenticity(conversation->ratchet, false);
		}
		if (message != NULL) {
			if (*message != NULL) {
				buffer_destroy_from_heap(*message);
			}
			*message = NULL;
		}
	}

	buffer_destroy_from_heap(current_receive_header_key);
	buffer_destroy_from_heap(next_receive_header_key);
	buffer_destroy_from_heap(header);
	buffer_destroy_from_heap(message_nonce);
	buffer_destroy_from_heap(their_signed_public_ephemeral);
	buffer_destroy_from_heap(message_key);

	return status;
}
