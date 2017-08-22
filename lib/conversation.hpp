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

namespace Molch {
	class Conversation {
		friend class ConversationStore;
	private:
		Conversation& move(Conversation&& conversation);

		void create(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral);

		int trySkippedHeaderAndMessageKeys(
			const Buffer& packet,
			Buffer& message,
			uint32_t& receive_message_number,
			uint32_t& previous_receive_message_number);

	public:
		Key<CONVERSATION_ID_SIZE,KeyType::Key> id; //unique id of a conversation, generated randomly
		std::unique_ptr<Ratchet> ratchet;

		/*
		 * Create a new conversation without sending or receiving anything.
		 */
		Conversation(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral);

		/*
		 * Start a new conversation where we are the sender.
		 */
		Conversation(
				const Buffer& message, //message we want to send to the receiver
				Buffer& packet, //output, free after use!
				const PublicKey& sender_public_identity, //who is sending this message?
				const PrivateKey& sender_private_identity,
				const PublicKey& receiver_public_identity,
				Buffer& receiver_prekey_list); //PREKEY_AMOUNT * PUBLIC_KEY_SIZE

		/*
		 * Start a new conversation where we are the receiver.
		 *
		 * Don't forget to destroy the return status with return_status_destroy_errors()
		 * if an error has occurred.
		 */
		Conversation(
				const Buffer& packet, //received packet
				Buffer& message, //output
				const PublicKey& receiver_public_identity,
				const PrivateKey& receiver_private_identity,
				PrekeyStore& receiver_prekeys); //prekeys of the receiver

		/*! Import a conversatoin from a Protobuf-C struct
		 * \param conversation_protobuf The protobuf-c struct to import from.
		 */
		Conversation(const ProtobufCConversation& conversation_protobuf);

		Conversation(Conversation&& conversation);
		Conversation(const Conversation& conversation) = delete;

		Conversation& operator=(Conversation&& conversation);
		Conversation& operator=(const Conversation& conversation) = delete;

		/*
		 * Send a message using an existing conversation.
		 *
		 * \return A packet containing the encrypted messge.
		 */
		Buffer send(
				const Buffer& message,
				const PublicKey * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
				const PublicKey * const public_ephemeral_key, //cann be nullptr, if not nullptr, this will be a prekey message
				const PublicKey * const public_prekey); //can be nullptr, if not nullptr, this will be a prekey message

		/*
		 * Receive and decrypt a message using an existing conversation.
		 *
		 * \return The message that has been decrypted.
		 */
		Buffer receive(
			const Buffer& packet, //received packet
			uint32_t& receive_message_number,
			uint32_t& previous_receive_message_number);

		/*! Export a conversation to a Protobuf-C struct.
		 * \return exported_conversation The exported conversation protobuf-c struct.
		 */
		std::unique_ptr<ProtobufCConversation,ConversationDeleter> exportProtobuf() const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif

