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
	Buffer id; //unique id of a conversation, generated randomly
	unsigned char id_storage[CONVERSATION_ID_SIZE];
	Ratchet *ratchet;
};

/*
 * Destroy a conversation.
 */
void conversation_destroy(conversation_t * const conversation) noexcept;

/*
 * Start a new conversation where we are the sender.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_start_send_conversation(
		conversation_t ** const conversation, //output, newly created conversation
		Buffer *const message, //message we want to send to the receiver
		std::unique_ptr<Buffer>& packet, //output, free after use!
		Buffer * const sender_public_identity, //who is sending this message?
		Buffer * const sender_private_identity,
		Buffer * const receiver_public_identity,
		Buffer * const receiver_prekey_list //PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		) noexcept __attribute__((warn_unused_result));

/*
 * Start a new conversation where we are the receiver.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_start_receive_conversation(
		conversation_t ** const conversation, //output, newly created conversation
		Buffer * const packet, //received packet
		Buffer ** message, //output, free after use!
		Buffer * const receiver_public_identity,
		Buffer * const receiver_private_identity,
		PrekeyStore * const receiver_prekeys //prekeys of the receiver
		) noexcept __attribute__((warn_unused_result));

/*
 * Send a message using an existing conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_send(
		conversation_t * const conversation,
		Buffer * const message,
		std::unique_ptr<Buffer>& packet, //output
		Buffer * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
		Buffer * const public_ephemeral_key, //cann be nullptr, if not nullptr, this will be a prekey message
		Buffer * const public_prekey //can be nullptr, if not nullptr, this will be a prekey message
		) noexcept __attribute__((warn_unused_result));

/*
 * Receive and decrypt a message using an existing conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status conversation_receive(
	conversation_t * const conversation,
	Buffer * const packet, //received packet
	uint32_t * const receive_message_number,
	uint32_t * const previous_receive_message_number,
	Buffer ** const message //output, free after use!
		) noexcept __attribute__((warn_unused_result));

/*! Export a conversation to a Protobuf-C struct.
 * \param conversation The conversation to export
 * \param exported_conversation The exported conversation protobuf-c struct.
 */
return_status conversation_export(
	conversation_t * const conversation,
	Conversation ** const exported_conversation) noexcept __attribute__((warn_unused_result));

/*! Import a conversatoin from a Protobuf-C struct
 * \param conversation The conversation to import to.
 * \param conversation_protobuf The protobuf-c struct to import from.
 * \param public_identity_key The public identity key of the owner of the conversation.
 * \return The status.
 */
return_status conversation_import(
	conversation_t ** const conversation,
	const Conversation * const conversation_protobuf) noexcept __attribute__((warn_unused_result));
#endif

