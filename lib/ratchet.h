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

extern "C" {
	#include <conversation.pb-c.h>
}
#include "constants.h"
#include "header-and-message-keystore.h"
#include "common.h"
#include "return-status.h"
#include "zeroed_malloc.h"

#ifndef LIB_RATCHET_H
#define LIB_RATCHET_H

typedef enum ratchet_header_decryptability {
	CURRENT_DECRYPTABLE, //decryptable with current receive header key
	NEXT_DECRYPTABLE, //decryptable with next receive header key
	UNDECRYPTABLE, //not decryptable
	NOT_TRIED //not tried to decrypt yet
} ratchet_header_decryptability;

class RatchetStorage {
	friend class Ratchet;

private:
	unsigned char root_key_storage[ROOT_KEY_SIZE]; //RK
	unsigned char purported_root_key_storage[ROOT_KEY_SIZE]; //RKp
	//header keys
	unsigned char send_header_key_storage[HEADER_KEY_SIZE];
	unsigned char receive_header_key_storage[HEADER_KEY_SIZE];
	unsigned char next_send_header_key_storage[HEADER_KEY_SIZE];
	unsigned char next_receive_header_key_storage[HEADER_KEY_SIZE];
	unsigned char purported_receive_header_key_storage[HEADER_KEY_SIZE];
	unsigned char purported_next_receive_header_key_storage[HEADER_KEY_SIZE];
	//chain keys
	unsigned char send_chain_key_storage[CHAIN_KEY_SIZE]; //CKs
	unsigned char receive_chain_key_storage[CHAIN_KEY_SIZE]; //CKr
	unsigned char purported_receive_chain_key_storage[CHAIN_KEY_SIZE]; //CKp
	//identity keys
	unsigned char our_public_identity_storage[PUBLIC_KEY_SIZE]; //DHIs
	unsigned char their_public_identity_storage[PUBLIC_KEY_SIZE]; //DHIr
	//ephemeral keys (ratchet keys)
	unsigned char our_private_ephemeral_storage[PRIVATE_KEY_SIZE]; //DHRs
	unsigned char our_public_ephemeral_storage[PUBLIC_KEY_SIZE]; //DHRs
	unsigned char their_public_ephemeral_storage[PUBLIC_KEY_SIZE]; //DHRr
	unsigned char their_purported_public_ephemeral_storage[PUBLIC_KEY_SIZE]; //DHp

	void init();

public:
	RatchetStorage();

	Buffer root_key; //RK
	Buffer purported_root_key; //RKp
	//header keys
	Buffer send_header_key;
	Buffer receive_header_key;
	Buffer next_send_header_key;
	Buffer next_receive_header_key;
	Buffer purported_receive_header_key;
	Buffer purported_next_receive_header_key;
	//chain keys
	Buffer send_chain_key; //CKs
	Buffer receive_chain_key; //CKr
	Buffer purported_receive_chain_key; //CKp
	//identity keys
	Buffer our_public_identity; //DHIs
	Buffer their_public_identity; //DHIr
	//ephemeral keys (ratchet keys)
	Buffer our_private_ephemeral; //DHRs
	Buffer our_public_ephemeral; //DHRs
	Buffer their_public_ephemeral; //DHRr
	Buffer their_purported_public_ephemeral; //DHp
};

class Ratchet {
private:
	void init();

	static void stageSkippedHeaderAndMessageKeys(
		HeaderAndMessageKeyStore& staging_area,
		Buffer * const output_chain_key, //output, CHAIN_KEY_SIZE
		Buffer * const output_message_key, //output, MESSAGE_KEY_SIZE
		const Buffer& current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const Buffer& chain_key);
	void commitSkippedHeaderAndMessageKeys();

public:
	std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>> storage;

	//message numbers
	uint32_t send_message_number; //Ns
	uint32_t receive_message_number; //Nr
	uint32_t purported_message_number; //Np
	uint32_t previous_message_number; //PNs (number of messages sent in previous chain)
	uint32_t purported_previous_message_number; //PNp
	//ratchet flag
	bool ratchet_flag;
	bool am_i_alice;
	bool received_valid; //is false until the validity of a received message has been verified until the validity of a received message has been verified,
	                     //this is necessary to be able to split key derivation from message
	                     //decryption
	ratchet_header_decryptability header_decryptable; //could the last received header be decrypted?
	//list of previous message and header keys
	HeaderAndMessageKeyStore skipped_header_and_message_keys; //skipped_HK_MK (list containing message keys for messages that weren't received)
	HeaderAndMessageKeyStore staged_header_and_message_keys; //this represents the staging area specified in the axolotl ratchet

	/*
	 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
	 *
	 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
	 * immediately deleted after deriving the initial root key though!)
	 */
	Ratchet(
			const Buffer& our_private_identity,
			const Buffer& our_public_identity,
			const Buffer& their_public_identity,
			const Buffer& our_private_ephemeral,
			const Buffer& our_public_ephemeral,
			const Buffer& their_public_ephemeral);

	/*! Import a ratchet from Protobuf-C
	 * NOTE: The public identity key is needed separately,
	 * because it is not contained in the Conversation
	 * Protobuf-C struct
	 * \param ratchet The Ratchet to imports
	 * \param conversation The Protobuf-C buffer.
	 */
	Ratchet(const Conversation& conversation);

	/*
	 * Get keys and metadata to send the next message.
	 */
	void send(
			Buffer& send_header_key, //HEADER_KEY_SIZE, HKs
			uint32_t& send_message_number, //Ns
			uint32_t& previous_send_message_number, //PNs
			Buffer& our_public_ephemeral, //DHRs
			Buffer& message_key //MESSAGE_KEY_SIZE, MK
			);

	/*
	 * Get a copy of the current and the next receive header key.
	 */
	void getReceiveHeaderKeys(
			Buffer& current_receive_header_key,
			Buffer& next_receive_header_key);

	/*
	 * Set if the header is decryptable with the current (state->receive_header_key)
	 * or next (next_receive_header_key) header key, or isn't decryptable.
	 */
	void setHeaderDecryptability(const ratchet_header_decryptability header_decryptable);

	/*
	 * First step after receiving a message: Calculate purported keys.
	 *
	 * This is only staged until it is later verified that the message was
	 * authentic.
	 *
	 * To verify that the message was authentic, encrypt it with the message key
	 * returned by this function and call ratchet_set_last_message_authenticity
	 * after having verified the message.
	 */
	void receive(
			Buffer& message_key, //used to get the message key back
			const Buffer& their_purported_public_ephemeral,
			const uint32_t purported_message_number,
			const uint32_t purported_previous_message_number);

	/*
	 * Call this function after trying to decrypt a message and pass it if
	 * the decryption was successful or if it wasn't.
	 */
	void setLastMessageAuthenticity(const bool valid);

	/*! Export a ratchet state to Protobuf-C
	 * NOTE: This doesn't fill the Id field of the struct.
	 * \return conversation The Conversation Protobuf-C struct.
	 */
	std::unique_ptr<Conversation,ConversationDeleter> exportProtobuf();
};
#endif
