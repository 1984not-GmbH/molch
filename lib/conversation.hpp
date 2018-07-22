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
#include "packet.hpp"
#include "prekey-store.hpp"

namespace Molch {
	struct ReceivedMessage {
		uint32_t message_number;
		uint32_t previous_message_number;
		Buffer message;
	};

	class Conversation {
		friend class ConversationStore;
	private:
		Conversation& move(Conversation&& conversation) noexcept;

		void create(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral);

		result<ReceivedMessage> internal_receive(const span<const std::byte> packet);
		result<ReceivedMessage> trySkippedHeaderAndMessageKeys(const span<const std::byte> packet);

		Key<CONVERSATION_ID_SIZE,KeyType::Key> id_storage; //unique id of a conversation, generated randomly
		Ratchet ratchet;

	public:
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
				const span<const std::byte> message, //message we want to send to the receiver
				Buffer& packet, //output, free after use!
				const PublicKey& sender_public_identity, //who is sending this message?
				const PrivateKey& sender_private_identity,
				const PublicKey& receiver_public_identity,
				const span<const std::byte> receiver_prekey_list); //PREKEY_AMOUNT * PUBLIC_KEY_SIZE

		/*
		 * Start a new conversation where we are the receiver.
		 *
		 * Don't forget to destroy the return status with return_status_destroy_errors()
		 * if an error has occurred.
		 */
		Conversation(
				const span<const std::byte> packet, //received packet
				Buffer& message, //output
				const PublicKey& receiver_public_identity,
				const PrivateKey& receiver_private_identity,
				PrekeyStore& receiver_prekeys); //prekeys of the receiver

		/*! Import a conversatoin from a Protobuf-C struct
		 * \param conversation_protobuf The protobuf-c struct to import from.
		 */
		Conversation(const ProtobufCConversation& conversation_protobuf);

		Conversation(Conversation&& conversation) noexcept;
		Conversation(const Conversation& conversation) = delete;

		Conversation& operator=(Conversation&& conversation) noexcept;
		Conversation& operator=(const Conversation& conversation) = delete;

		const Key<CONVERSATION_ID_SIZE,KeyType::Key>& id() const;

		/*
		 * Send a message using an existing conversation.
		 *
		 * \param message The message to send.
		 * \param prekey_metadata Prekey metadata in case of prekey messages
		 * \return A packet containing the encrypted messge.
		 */
		result<Buffer> send(const span<const std::byte> message, const std::optional<PrekeyMetadata>& prekey_metadata);

		/*
		 * Receive and decrypt a message using an existing conversation.
		 *
		 * \return The message that has been decrypted.
		 */
		result<ReceivedMessage> receive(const span<const std::byte> packet);

		/*! Export a conversation to a Protobuf-C struct.
		 * \return exported_conversation The exported conversation protobuf-c struct.
		 */
		ProtobufCConversation* exportProtobuf(Arena& arena) const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif

