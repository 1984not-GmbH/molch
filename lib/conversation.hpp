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

	struct SendConversation;
	struct ReceiveConversation;

	class Conversation {
	private:
		Conversation& move(Conversation&& conversation) noexcept;

		result<ReceivedMessage> internal_receive(const span<const std::byte> packet);
		result<ReceivedMessage> trySkippedHeaderAndMessageKeys(const span<const std::byte> packet);

		EmptyableKey<CONVERSATION_ID_SIZE,KeyType::Key> id_storage; //unique id of a conversation, generated randomly
		Ratchet ratchet;

		Conversation(uninitialized_t uninitialized) noexcept;

	public:

		Conversation() = delete;

		static result<Conversation> create(
			const PrivateKey& our_private_identity,
			const EmptyablePublicKey& our_public_identity,
			const EmptyablePublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const EmptyablePublicKey& our_public_ephemeral,
			const EmptyablePublicKey& their_public_ephemeral);

		static result<SendConversation> createSendConversation(
				const span<const std::byte> message, //message we want to send to the receiver
				const EmptyablePublicKey& sender_public_identity, //who is sending this message?
				const PrivateKey& sender_private_identity,
				const EmptyablePublicKey& receiver_public_identity,
				const span<const std::byte> receiver_prekey_list); //PREKEY_AMOUNT * PUBLIC_KEY_SIZE

		/*
		 * Start a new conversation where we are the receiver.
		 *
		 * Don't forget to destroy the return status with return_status_destroy_errors()
		 * if an error has occurred.
		 */
		static result<ReceiveConversation> createReceiveConversation(
				const span<const std::byte> packet,
				const EmptyablePublicKey& receiver_public_identity,
				const PrivateKey& receiver_private_identity,
				PrekeyStore& receiver_prekeys);

		/*! Import a conversatoin from a Protobuf-C struct
		 * \param conversation_protobuf The protobuf-c struct to import from.
		 *
		 * \return The imported conversation
		 */
		static result<Conversation> import(const ProtobufCConversation& conversation_protobuf);

		Conversation(Conversation&& conversation) noexcept;
		Conversation(const Conversation& conversation) = delete;

		Conversation& operator=(Conversation&& conversation) noexcept;
		Conversation& operator=(const Conversation& conversation) = delete;

		const EmptyableKey<CONVERSATION_ID_SIZE,KeyType::Key>& id() const;

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
		result<ProtobufCConversation*> exportProtobuf(Arena& arena) const;

		std::ostream& print(std::ostream& stream) const;
	};

	struct SendConversation {
		Buffer packet;
		Conversation conversation;

		SendConversation(Buffer&& packet, Conversation&& conversation) noexcept;
	};

	struct ReceiveConversation {
		Buffer message;
		Conversation conversation;

		ReceiveConversation(Buffer&& message, Conversation&& conversation) noexcept;
	};
}
#endif

