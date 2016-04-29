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

#include <stdbool.h>

#include "constants.h"
#include "header-and-message-keystore.h"
#include "return-status.h"

#ifndef LIB_RATCHET_H
#define LIB_RATCHET_H

typedef enum ratchet_header_decryptability {
	CURRENT_DECRYPTABLE, //decryptable with current receive header key
	NEXT_DECRYPTABLE, //decryptable with next receive header key
	UNDECRYPTABLE, //not decryptable
	NOT_TRIED //not tried to decrypt yet
} ratchet_header_decryptability;

//struct that represents the state of a conversation
typedef struct ratchet_state {
	buffer_t root_key[1]; //RK
	const unsigned char root_key_storage[ROOT_KEY_SIZE];
	buffer_t purported_root_key[1]; //RKp
	const unsigned char purported_root_key_storage[ROOT_KEY_SIZE];
	//header keys
	buffer_t send_header_key[1];
	const unsigned char send_header_key_storage[HEADER_KEY_SIZE];
	buffer_t receive_header_key[1];
	const unsigned char receive_header_key_storage[HEADER_KEY_SIZE];
	buffer_t next_send_header_key[1];
	const unsigned char next_send_header_key_storage[HEADER_KEY_SIZE];
	buffer_t next_receive_header_key[1];
	const unsigned char next_receive_header_key_storage[HEADER_KEY_SIZE];
	buffer_t purported_receive_header_key[1];
	const unsigned char purported_receive_header_key_storage[HEADER_KEY_SIZE];
	buffer_t purported_next_receive_header_key[1];
	const unsigned char purported_next_receive_header_key_storage[HEADER_KEY_SIZE];
	//chain keys
	buffer_t send_chain_key[1]; //CKs
	const unsigned char send_chain_key_storage[CHAIN_KEY_SIZE];
	buffer_t receive_chain_key[1]; //CKr
	const unsigned char receive_chain_key_storage[CHAIN_KEY_SIZE];
	buffer_t purported_receive_chain_key[1]; //CKp
	const unsigned char purported_receive_chain_key_storage[CHAIN_KEY_SIZE];
	//identity keys
	buffer_t our_public_identity[1]; //DHIs
	const unsigned char our_public_identity_storage[PUBLIC_KEY_SIZE];
	buffer_t their_public_identity[1]; //DHIr
	const unsigned char their_public_identity_storage[PUBLIC_KEY_SIZE];
	//ephemeral keys (ratchet keys)
	buffer_t our_private_ephemeral[1]; //DHRs
	const unsigned char our_private_ephemeral_storage[PRIVATE_KEY_SIZE];
	buffer_t our_public_ephemeral[1]; //DHRs
	const unsigned char our_public_ephemeral_storage[PUBLIC_KEY_SIZE];
	buffer_t their_public_ephemeral[1]; //DHRr
	const unsigned char their_public_ephemeral_storage[PUBLIC_KEY_SIZE];
	buffer_t their_purported_public_ephemeral[1]; //DHp
	const unsigned char their_purported_public_ephemeral_storage[PUBLIC_KEY_SIZE];
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
	header_and_message_keystore skipped_header_and_message_keys[1]; //skipped_HK_MK (list containing message keys for messages that weren't received)
	header_and_message_keystore staged_header_and_message_keys[1]; //this represents the staging area specified in the axolotl ratchet
} ratchet_state;

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 *
 * The return value is a valid ratchet state or NULL if an error occured.
 */
return_status ratchet_create(
		ratchet_state ** const ratchet,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) __attribute__((warn_unused_result));

/*
 * Get keys and metadata to send the next message.
 */
return_status ratchet_send(
		ratchet_state *state,
		buffer_t * const send_header_key, //HEADER_KEY_SIZE, HKs
		uint32_t * const send_message_number, //Ns
		uint32_t * const previous_send_message_number, //PNs
		buffer_t * const our_public_ephemeral, //DHRs
		buffer_t * const message_key //MESSAGE_KEY_SIZE, MK
		) __attribute__((warn_unused_result));

/*
 * Get a copy of the current and the next receive header key.
 */
return_status ratchet_get_receive_header_keys(
		buffer_t * const current_receive_header_key,
		buffer_t * const next_receive_header_key,
		ratchet_state *state) __attribute__((warn_unused_result));

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
return_status ratchet_set_header_decryptability(
		ratchet_state *ratchet,
		ratchet_header_decryptability header_decryptable) __attribute__((warn_unused_result));

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
return_status ratchet_receive(
		ratchet_state *state,
		buffer_t * const message_key, //used to get the message key back
		const buffer_t * const their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) __attribute__((warn_unused_result));

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
int ratchet_set_last_message_authenticity(
		ratchet_state * const ratchet,
		bool valid) __attribute__((warn_unused_result));

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state);

/*
 * Serialise a ratchet into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *ratchet_json_export(const ratchet_state * const state, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialise a ratchet (import from JSON).
 */
ratchet_state *ratchet_json_import(const mcJSON * const json) __attribute__((warn_unused_result));
#endif
