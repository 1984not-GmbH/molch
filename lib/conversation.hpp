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

#ifndef LIB_CONVERSATION_H
#define LIB_CONVERSATION_H

#include <ostream>

#include "constants.h"
#include "ratchet.hpp"
#include "prekey-store.hpp"

class ConversationT {
	friend class ConversationStore;
private:
	ConversationT& move(ConversationT&& conversation);

	void create(
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral);

	int trySkippedHeaderAndMessageKeys(
		const Buffer& packet,
		std::unique_ptr<Buffer>& message,
		uint32_t& receive_message_number,
		uint32_t& previous_receive_message_number);

	unsigned char id_storage[CONVERSATION_ID_SIZE];

public:

	Buffer id{this->id_storage, sizeof(this->id_storage), 0}; //unique id of a conversation, generated randomly
	std::unique_ptr<Ratchet> ratchet;

	/*
	 * Create a new conversation without sending or receiving anything.
	 */
	ConversationT(
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral);

	/*
	 * Start a new conversation where we are the sender.
	 */
	ConversationT(
			const Buffer& message, //message we want to send to the receiver
			std::unique_ptr<Buffer>& packet, //output, free after use!
			const Buffer& sender_public_identity, //who is sending this message?
			const Buffer& sender_private_identity,
			const Buffer& receiver_public_identity,
			Buffer& receiver_prekey_list); //PREKEY_AMOUNT * PUBLIC_KEY_SIZE

	/*
	 * Start a new conversation where we are the receiver.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	ConversationT(
			const Buffer& packet, //received packet
			std::unique_ptr<Buffer>& message, //output
			const Buffer& receiver_public_identity,
			const Buffer& receiver_private_identity,
			PrekeyStore& receiver_prekeys); //prekeys of the receiver

	/*! Import a conversatoin from a Protobuf-C struct
	 * \param conversation_protobuf The protobuf-c struct to import from.
	 */
	ConversationT(const Conversation& conversation_protobuf);

	ConversationT(ConversationT&& conversation);
	ConversationT(const ConversationT& conversation) = delete;

	ConversationT& operator=(ConversationT&& conversation);
	ConversationT& operator=(const ConversationT& conversation) = delete;

	/*
	 * Send a message using an existing conversation.
	 *
	 * \return A packet containing the encrypted messge.
	 */
	std::unique_ptr<Buffer> send(
			const Buffer& message,
			const Buffer * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
			const Buffer * const public_ephemeral_key, //cann be nullptr, if not nullptr, this will be a prekey message
			const Buffer * const public_prekey); //can be nullptr, if not nullptr, this will be a prekey message

	/*
	 * Receive and decrypt a message using an existing conversation.
	 *
	 * \return The message that has been decrypted.
	 */
	std::unique_ptr<Buffer> receive(
		const Buffer& packet, //received packet
		uint32_t& receive_message_number,
		uint32_t& previous_receive_message_number);

	/*! Export a conversation to a Protobuf-C struct.
	 * \return exported_conversation The exported conversation protobuf-c struct.
	 */
	std::unique_ptr<Conversation,ConversationDeleter> exportProtobuf() const;

	std::ostream& print(std::ostream& stream) const;
};
#endif

