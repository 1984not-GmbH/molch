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

#ifndef LIB_RATCHET_H
#define LIB_RATCHET_H

#include <ostream>
#include <optional>

#include "molch/constants.h"
#include "header-and-message-keystore.hpp"
#include "return-status.hpp"
#include "protobuf.hpp"
#include "key.hpp"
#include "protobuf-arena.hpp"

namespace Molch {
	class RatchetStorage {
	public:
		EmptyableRootKey root_key; //RK
		EmptyableRootKey purported_root_key; //RKp
		//header keys
		std::optional<EmptyableHeaderKey> send_header_key;
		EmptyableHeaderKey receive_header_key;
		EmptyableHeaderKey next_send_header_key;
		EmptyableHeaderKey next_receive_header_key;
		EmptyableHeaderKey purported_receive_header_key;
		EmptyableHeaderKey purported_next_receive_header_key;
		//chain keys
		EmptyableChainKey send_chain_key; //CKs
		EmptyableChainKey receive_chain_key; //CKr
		EmptyableChainKey purported_receive_chain_key; //CKp
		//identity keys
		PublicKey our_public_identity; //DHIs
		PublicKey their_public_identity; //DHIr
		//ephemeral keys (ratchet keys)
		PrivateKey our_private_ephemeral; //DHRs
		PublicKey our_public_ephemeral; //DHRs
		PublicKey their_public_ephemeral; //DHRr
		std::optional<PublicKey> their_purported_public_ephemeral; //DHp
	};

	class Ratchet {
	private:
		void init();

		void commitSkippedHeaderAndMessageKeys();

	public:
		std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>> storage;

		//message numbers
		uint32_t send_message_number{0}; //Ns
		uint32_t receive_message_number{0}; //Nr
		uint32_t purported_message_number{0}; //Np
		uint32_t previous_message_number{0}; //PNs (number of messages sent in previous chain)
		uint32_t purported_previous_message_number{0}; //PNp
		//ratchet flag
		bool ratchet_flag{false};
		enum class Role : bool {
			ALICE = true,
			BOB = false
		};
		Role role{Role::BOB};
		bool received_valid{false}; //is false until the validity of a received message has been verified until the validity of a received message has been verified,
							 //this is necessary to be able to split key derivation from message
							 //decryption
		enum class HeaderDecryptability{
			CURRENT_DECRYPTABLE, //decryptable with current receive header key
			NEXT_DECRYPTABLE, //decryptable with next receive header key
			UNDECRYPTABLE, //not decryptable
			NOT_TRIED //not tried to decrypt yet
		};
		HeaderDecryptability header_decryptable{HeaderDecryptability::NOT_TRIED}; //could the last received header be decrypted?
		//list of previous message and header keys
		HeaderAndMessageKeyStore skipped_header_and_message_keys; //skipped_HK_MK (list containing message keys for messages that weren't received)
		HeaderAndMessageKeyStore staged_header_and_message_keys; //this represents the staging area specified in the axolotl ratchet

		Ratchet();

		/*
		 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
		 *
		 * All the keys will be copied so you can free the buffers afterwards.
		 */
		static result<Ratchet> create(
				const PrivateKey& our_private_identity,
				const PublicKey& our_public_identity,
				const PublicKey& their_public_identity,
				const PrivateKey& our_private_ephemeral,
				const PublicKey& our_public_ephemeral,
				const PublicKey& their_public_ephemeral);

		/*! Import a ratchet from Protobuf-C
		 * NOTE: The public identity key is needed separately,
		 * because it is not contained in the Conversation
		 * Protobuf-C struct
		 * \param conversation The Protobuf-C buffer.
		 */
		static result<Ratchet> import(const ProtobufCConversation& conversation);

		Ratchet(const Ratchet& ratchet) = delete;
		Ratchet(Ratchet&& ratchet) = default;
		Ratchet& operator=(const Ratchet& ratchet) = delete;
		Ratchet& operator=(Ratchet&& ratchet) = default;

		struct SendData {
			uint32_t message_number;
			uint32_t previous_message_number;
			PublicKey ephemeral;
			MessageKey message_key;
			EmptyableHeaderKey header_key;
		};

		/*
		 * Get keys and metadata to send the next message.
		 */
		result<SendData> getSendData();

		struct ReceiveHeaderKeys {
			EmptyableHeaderKey current;
			EmptyableHeaderKey next;
		};

		/*
		 * Get a copy of the current and the next receive header key.
		 */
		ReceiveHeaderKeys getReceiveHeaderKeys() const noexcept;

		/*
		 * Set if the header is decryptable with the current (state->receive_header_key)
		 * or next (next_receive_header_key) header key, or isn't decryptable.
		 */
		result<void> setHeaderDecryptability(const HeaderDecryptability header_decryptable) noexcept;

		/*
		 * First step after receiving a message: Calculate purported keys.
		 *
		 * This is only staged until it is later verified that the message was
		 * authentic.
		 *
		 * To verify that the message was authentic, decrypt it with the message key
		 * returned by this function and call ratchet_set_last_message_authenticity
		 * after having verified the message.
		 */
		result<MessageKey> receive(
				const PublicKey& their_purported_public_ephemeral,
				const uint32_t purported_message_number,
				const uint32_t purported_previous_message_number);

		/*
		 * Call this function after trying to decrypt a message and pass it if
		 * the decryption was successful or if it wasn't.
		 */
		result<void> setLastMessageAuthenticity(const bool valid) noexcept;

		/*! Export a ratchet state to Protobuf-C
		 * NOTE: This doesn't fill the Id field of the struct.
		 * \return conversation The Conversation Protobuf-C struct.
		 */
		result<ProtobufCConversation*> exportProtobuf(Arena& arena) const;

		std::ostream& print(std::ostream& stream) const;
	};
}
#endif
