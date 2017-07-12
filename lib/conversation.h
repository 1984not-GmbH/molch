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
#include "ratchet.h"
#include "prekey-store.h"
#include "common.h"

#ifndef LIB_CONVERSATION_H
#define LIB_CONVERSATION_H

typedef struct conversation_t conversation_t;
struct conversation_t {
	conversation_t *previous;
	conversation_t *next;
	buffer_t id[1]; //unique id of a conversation, generated randomly
	unsigned char id_storage[CONVERSATION_ID_SIZE];
	ratchet_state *ratchet;
};

/*
 * Destroy a conversation.
 */
void conversation_destroy(conversation_t * const conversation);

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
		) __attribute__((warn_unused_result));

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
		) __attribute__((warn_unused_result));

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
		const buffer_t * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
		const buffer_t * const public_ephemeral_key, //cann be nullptr, if not nullptr, this will be a prekey message
		const buffer_t * const public_prekey //can be nullptr, if not nullptr, this will be a prekey message
		) __attribute__((warn_unused_result));

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
	buffer_t ** const message //output, free after use!
		) __attribute__((warn_unused_result));

/*! Export a conversation to a Protobuf-C struct.
 * \param conversation The conversation to export
 * \param exported_conversation The exported conversation protobuf-c struct.
 */
return_status conversation_export(
	const conversation_t * const conversation,
	Conversation ** const exported_conversation) __attribute__((warn_unused_result));

/*! Import a conversatoin from a Protobuf-C struct
 * \param conversation The conversation to import to.
 * \param conversation_protobuf The protobuf-c struct to import from.
 * \param public_identity_key The public identity key of the owner of the conversation.
 * \return The status.
 */
return_status conversation_import(
	conversation_t ** const conversation,
	const Conversation * const conversation_protobuf) __attribute__((warn_unused_result));
#endif

