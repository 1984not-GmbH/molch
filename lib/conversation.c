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

	status = ratchet_create(
			&((*conversation)->ratchet),
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create ratchet.");

cleanup:
	if (status.status != 0) {
		if ((conversation != NULL) && (*conversation != NULL)) {
			free_and_null(*conversation);
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

		free_and_null(conversation);

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
	buffer_destroy_from_heap_and_null(sender_public_ephemeral);
	buffer_destroy_from_heap_and_null(sender_private_ephemeral);

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
	uint32_t receive_message_number = 0;
	uint32_t previous_receive_message_number = 0;

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

	*conversation = NULL;

	//get the senders keys and our public prekey from the packet
	molch_message_type packet_type;
	uint32_t current_protocol_version;
	uint32_t highest_supported_protocol_version;
	status = packet_get_metadata_without_verification(
			&current_protocol_version,
			&highest_supported_protocol_version,
			&packet_type,
			packet,
			sender_public_identity,
			sender_public_ephemeral,
			receiver_public_prekey);
	throw_on_error(GENERIC_ERROR, "Failed to get packet metadata.");

	if (packet_type != PREKEY_MESSAGE) {
		throw(INVALID_VALUE, "Packet is not a prekey message.");
	}

	//get the private prekey that corresponds to the public prekey used in the message
	status = prekey_store_get_prekey(
			receiver_prekeys,
			receiver_public_prekey,
			receiver_private_prekey);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get public prekey.");

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
			&receive_message_number,
			&previous_receive_message_number,
			message);
	throw_on_error(RECEIVE_ERROR, "Failed to receive message.");

cleanup:
	buffer_destroy_from_heap_and_null(receiver_public_prekey);
	buffer_destroy_from_heap_and_null(receiver_private_prekey);
	buffer_destroy_from_heap_and_null(sender_public_ephemeral);
	buffer_destroy_from_heap_and_null(sender_public_identity);

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
	buffer_t *header = NULL;

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

	molch_message_type packet_type = NORMAL_MESSAGE;
	//check if this is a prekey message
	if (public_identity_key != NULL) {
		packet_type = PREKEY_MESSAGE;
	}

	*packet = NULL;

	uint32_t send_message_number;
	uint32_t previous_send_message_number;
	status = ratchet_send(
			conversation->ratchet,
			send_header_key,
			&send_message_number,
			&previous_send_message_number,
			send_ephemeral_key,
			send_message_key);
	throw_on_error(SEND_ERROR, "Failed to get send keys.");

	//create the header
	status = header_construct(
			&header,
			send_ephemeral_key,
			send_message_number,
			previous_send_message_number);
	throw_on_error(CREATION_ERROR, "Failed to construct header.");

	status = packet_encrypt(
			packet,
			packet_type,
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
				buffer_destroy_from_heap_and_null(*packet);
			}
		}
	}
	buffer_destroy_from_heap_and_null(send_header_key);
	buffer_destroy_from_heap_and_null(send_message_key);
	buffer_destroy_from_heap_and_null(send_ephemeral_key);
	if (header != NULL) {
		buffer_destroy_from_heap_and_null(header);
	}

	return status;
}

/*
 * Try to decrypt a packet with skipped over header and message keys.
 * This corresponds to "try_skipped_header_and_message_keys" from the
 * Axolotl protocol description.
 *
 * Returns 0, if it was able to decrypt the packet.
 */
int try_skipped_header_and_message_keys(
		header_and_message_keystore * const skipped_keys,
		const buffer_t * const packet,
		buffer_t ** const message,
		uint32_t * const receive_message_number,
		uint32_t * const previous_receive_message_number) {
	//create buffers
	buffer_t *header = NULL;
	buffer_t *their_signed_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	return_status status = return_status_init();
	header_and_message_keystore_node* node = skipped_keys->head;
	for (size_t i = 0; (i < skipped_keys->length) && (node != NULL); i++, node = node->next) {
		status = packet_decrypt_header(
				&header,
				packet,
				node->header_key);
		if (status.status == SUCCESS) {
			status = packet_decrypt_message(
					message,
					packet,
					node->message_key);
			if (status.status == SUCCESS) {
				header_and_message_keystore_remove(skipped_keys, node);

				status = header_extract(
						their_signed_public_ephemeral,
						receive_message_number,
						previous_receive_message_number,
						header);
				throw_on_error(GENERIC_ERROR, "Failed to extract data from header.");

				goto cleanup;
			}
		}
		return_status_destroy_errors(&status);
	}

	status.status = NOT_FOUND;

cleanup:
	if (header != NULL) {
		buffer_destroy_from_heap_and_null(header);
	}
	on_error(
		if ((message != NULL) && (*message != NULL)) {
			buffer_destroy_from_heap_and_null(*message);
		}
	);
	buffer_destroy_from_heap_and_null(their_signed_public_ephemeral);

	return_status_destroy_errors(&status);

	return status.status;
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
	uint32_t * const receive_message_number,
	uint32_t * const previous_receive_message_number,
	buffer_t ** const message) { //output, free after use!

	//create buffers
	buffer_t *current_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *next_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *header = NULL;
	buffer_t *their_signed_public_ephemeral = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);

	return_status status = return_status_init();

	if ((conversation == NULL)
			|| (packet == NULL)
			|| (message == NULL)
			|| (receive_message_number == NULL)
			|| (previous_receive_message_number == NULL)) {
		throw(INVALID_INPUT, "Invalid input to conversation_receive.");
	}

	*message = buffer_create_on_heap(packet->content_length, 0);

	int status_int = 0;
	status_int = try_skipped_header_and_message_keys(
			conversation->ratchet->skipped_header_and_message_keys,
			packet,
			message,
			receive_message_number,
			previous_receive_message_number);
	if (status_int == 0) {
		// found a key and successfully decrypted the message
		goto cleanup;
	}

	status = ratchet_get_receive_header_keys(
			current_receive_header_key,
			next_receive_header_key,
			conversation->ratchet);
	throw_on_error(DATA_FETCH_ERROR, "Failed to get receive header keys.");

	//try to decrypt the packet header with the current receive header key
	status = packet_decrypt_header(
			&header,
			packet,
			current_receive_header_key);
	if (status.status == SUCCESS) {
		status = ratchet_set_header_decryptability(
				conversation->ratchet,
				CURRENT_DECRYPTABLE);
		throw_on_error(DATA_SET_ERROR, "Failed to set decryptability to CURRENT_DECRYPTABLE.");
	} else {
		return_status_destroy_errors(&status); //free the error stack to avoid memory leak.

		//since this failed, try to decrypt it with the next receive header key
		status = packet_decrypt_header(
				&header,
				packet,
				next_receive_header_key);
		if (status.status == SUCCESS) {
			status = ratchet_set_header_decryptability(
					conversation->ratchet,
					NEXT_DECRYPTABLE);
			throw_on_error(DATA_SET_ERROR, "Failed to set decryptability to NEXT_DECRYPTABLE.");
		} else {
			return_status decryptability_status = return_status_init();
			decryptability_status = ratchet_set_header_decryptability(
					conversation->ratchet,
					UNDECRYPTABLE);
			return_status_destroy_errors(&decryptability_status);
			throw(DECRYPT_ERROR, "Header undecryptable.");
		}
	}

	//extract data from the header
	uint32_t local_receive_message_number;
	uint32_t local_previous_receive_message_number;
	status = header_extract(
			their_signed_public_ephemeral,
			&local_receive_message_number,
			&local_previous_receive_message_number,
			header);
	throw_on_error(GENERIC_ERROR, "Failed to extract data from header.");

	//and now decrypt the message with the message key
	//now we have all the data we need to advance the ratchet
	//so let's do that
	status = ratchet_receive(
			conversation->ratchet,
			message_key,
			their_signed_public_ephemeral,
			local_receive_message_number,
			local_previous_receive_message_number);
	throw_on_error(DECRYPT_ERROR, "Failed to get decryption keys.");

	status = packet_decrypt_message(
			message,
			packet,
			message_key);
	on_error(
		return_status authenticity_status = return_status_init();
		authenticity_status = ratchet_set_last_message_authenticity(conversation->ratchet, false);
		return_status_destroy_errors(&authenticity_status);
		throw(DECRYPT_ERROR, "Failed to decrypt message.");
	);

	status = ratchet_set_last_message_authenticity(conversation->ratchet, true);
	throw_on_error(DATA_SET_ERROR, "Failed to set message authenticity.");

	*receive_message_number = local_receive_message_number;
	*previous_receive_message_number = local_previous_receive_message_number;

cleanup:
	on_error(
		return_status authenticity_status = return_status_init();
		if (conversation != NULL) {
			authenticity_status = ratchet_set_last_message_authenticity(conversation->ratchet, false);
			return_status_destroy_errors(&authenticity_status);
		}
		if (message != NULL) {
			if (*message != NULL) {
				buffer_destroy_from_heap_and_null(*message);
			}
		}
	);

	buffer_destroy_from_heap_and_null(current_receive_header_key);
	buffer_destroy_from_heap_and_null(next_receive_header_key);
	if (header != NULL) {
		buffer_destroy_from_heap_and_null(header);
	}
	buffer_destroy_from_heap_and_null(their_signed_public_ephemeral);
	buffer_destroy_from_heap_and_null(message_key);

	return status;
}
