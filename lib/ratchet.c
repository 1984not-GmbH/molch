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

#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "ratchet.h"
#include "diffie-hellman.h"
#include "hkdf.h"
#include "key-derivation.h"

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 *
 * The return value is a valid ratchet state or NULL if an error occured.
 */
ratchet_state* ratchet_create(
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const their_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		bool am_i_alice) {
	ratchet_state *state = malloc(sizeof(ratchet_state));

	//initialise chain and root key
	state->root_key = malloc(crypto_secretbox_KEYBYTES);
	state->send_chain_key = malloc(crypto_secretbox_KEYBYTES);
	state->receive_chain_key = malloc(crypto_secretbox_KEYBYTES);
	state->purported_receive_chain_key = malloc(crypto_secretbox_KEYBYTES);

	//derive initial chain and root key
	int status = derive_initial_root_and_chain_key(
			state->root_key,
			state->send_chain_key,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_memzero(state->root_key, crypto_secretbox_KEYBYTES);
		sodium_memzero(state->send_chain_key, crypto_secretbox_KEYBYTES);
		free(state);
		return NULL;
	}

	//copy send_chain_key -> receive_chain_key
	//TODO This kind of deviates from axolotl because the first chain key is identical for
	//send/receive, only one of them is used though
	memcpy(state->receive_chain_key, state->send_chain_key, crypto_secretbox_KEYBYTES);

	//copy keys into state
	//our public identity
	state->our_public_identity = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->our_public_identity, our_public_identity, crypto_box_PUBLICKEYBYTES);
	//their_public_identity
	state->their_public_identity = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->their_public_identity, their_public_identity, crypto_box_PUBLICKEYBYTES);
	//our_private_ephemeral
	state->our_private_ephemeral = malloc(crypto_box_SECRETKEYBYTES);
	memcpy(state->our_private_ephemeral, our_private_ephemeral, crypto_box_SECRETKEYBYTES);
	//our_public_ephemeral
	state->our_public_ephemeral = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->our_public_ephemeral, our_public_ephemeral, crypto_box_PUBLICKEYBYTES);
	//their_public_ephemeral
	state->their_public_ephemeral = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->their_public_ephemeral, their_public_ephemeral, crypto_box_PUBLICKEYBYTES);

	//initialise message keystore for skipped messages
	state->skipped_message_keys = message_keystore_init();
	state->purported_message_keys = message_keystore_init();

	//set other state
	state->am_i_alice = am_i_alice;
	state->ratchet_flag = am_i_alice;
	state->received_valid = true; //allowing the receival of new messages
	state->send_message_number = 0;
	state->receive_message_number = 0;
	state->previous_message_number = 0;

	return state;

}

/*
 * Create message key to encrypt the next sent message with.
 */
int ratchet_next_send_key(
		unsigned char * const next_message_key,
		bool *new_ephemeral,
		ratchet_state *state) {
	int status;
	*new_ephemeral = false;
	if (state->ratchet_flag) {
		//generate new ephemeral key
		status = crypto_box_keypair(state->our_public_ephemeral, state->our_private_ephemeral);
		if (status != 0) {
			return status;
		}
		*new_ephemeral = true;

		//derive next root key and send chain key
		//RK, CKs = HKDF(DH(DHs, DHr))
		unsigned char previous_root_key[crypto_secretbox_KEYBYTES];
		memcpy(previous_root_key, state->root_key, sizeof(previous_root_key));
		status = derive_root_and_chain_key(
				state->root_key,
				state->send_chain_key,
				state->our_private_ephemeral,
				state->our_public_ephemeral,
				state->their_public_ephemeral,
				previous_root_key,
				state->am_i_alice);
		sodium_memzero(previous_root_key, sizeof(previous_root_key));
		if (status != 0) {
			return status;
		}

		state->previous_message_number = state->send_message_number;
		state->send_message_number = 0;
		state->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, 0x00)
	status = derive_message_key(
			next_message_key,
			state->send_chain_key);
	if (status != 0) {
		return status;
	}

	state->send_message_number++;

	//derive next chain key
	//CKs = HMAC-HASH(CKs, 0x01)
	unsigned char old_chain_key[crypto_secretbox_KEYBYTES];
	memcpy(old_chain_key, state->send_chain_key, sizeof(old_chain_key));
	status = derive_chain_key(
			state->send_chain_key,
			old_chain_key);
	sodium_memzero(old_chain_key, sizeof(old_chain_key));

	return status;
}

/*
 * This corresponds to "stage_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Calculate all the message keys up the the purported message number
 * and save them in the current ratchet state's staging area.
 *
 * TODO: This could easily be used to make clients hang. Because there are
 * currently no header keys in use, an attacker could specify an arbitrarily
 * high purported message number, thereby making this function calculate
 * all of them -> program hangs. Current workaround: Limiting number
 * of message keys that get precalculated.
 */
int stage_skipped_message_keys(
		const unsigned int purported_message_number,
		const unsigned char  * const receive_chain_key,
		ratchet_state *state) {
	//limit number of message keys to calculate
	const unsigned int LIMIT = 100;
	if ((purported_message_number - state->receive_message_number) > LIMIT) {
		return -10;
	}

	//copy current chain key to purported chain key
	unsigned char purported_previous_chain_key[crypto_secretbox_KEYBYTES];
	unsigned char purported_current_chain_key[crypto_secretbox_KEYBYTES];
	memcpy(purported_previous_chain_key, receive_chain_key, sizeof(purported_previous_chain_key));

	//message key buffer
	unsigned char message_key_buffer[crypto_secretbox_KEYBYTES];

	//create all message keys
	int status;
	unsigned int pos;
	for (pos = state->receive_message_number; pos <= purported_message_number; pos++) {
		status = derive_chain_key(purported_current_chain_key, purported_previous_chain_key);
		if (status != 0) {
			sodium_memzero(purported_previous_chain_key, sizeof(purported_previous_chain_key));
			sodium_memzero(purported_current_chain_key, sizeof(purported_current_chain_key));
			return status;
		}

		status = derive_message_key(message_key_buffer, purported_current_chain_key);
		if (status != 0) {
			sodium_memzero(purported_previous_chain_key, sizeof(purported_previous_chain_key));
			sodium_memzero(purported_current_chain_key, sizeof(purported_current_chain_key));
			sodium_memzero(message_key_buffer, sizeof(message_key_buffer));
			return status;
		}

		//add message key to list of purported message keys
		status = message_keystore_add(
				&(state->purported_message_keys),
				message_key_buffer);
		sodium_memzero(message_key_buffer, sizeof(message_key_buffer));
		if (status != 0) {
			sodium_memzero(purported_previous_chain_key, sizeof(purported_previous_chain_key));
			sodium_memzero(purported_current_chain_key, sizeof(purported_current_chain_key));
			return status;
		}

		//shift chain keys
		memcpy(purported_previous_chain_key, purported_current_chain_key, sizeof(purported_previous_chain_key));
	}

	//copy chain key to purported_receive_chain_key (this will be used in commit_skipped_message_keys)
	memcpy(state->purported_receive_chain_key, purported_current_chain_key, sizeof(purported_current_chain_key));

	sodium_memzero(purported_previous_chain_key, sizeof(purported_previous_chain_key));
	sodium_memzero(purported_current_chain_key, sizeof(purported_current_chain_key));

	return 0;
}

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state) {
	//free keys
	//root key
	sodium_memzero(state->root_key, crypto_secretbox_KEYBYTES);
	free(state->root_key);
	//our public identity
	free(state->our_public_identity);
	//their_public_identity
	free(state->their_public_identity);
	//our private ephemeral
	sodium_memzero(state->our_private_ephemeral, crypto_box_SECRETKEYBYTES);
	free(state->our_private_ephemeral);
	//our public ephemeral
	free(state->our_public_ephemeral);
	//their public ephemeral
	free(state->their_public_ephemeral);

	//chain keys
	sodium_memzero(state->send_chain_key, crypto_secretbox_KEYBYTES);
	free(state->send_chain_key);
	sodium_memzero(state->receive_chain_key, crypto_secretbox_KEYBYTES);
	free(state->receive_chain_key);
	sodium_memzero(state->purported_receive_chain_key, crypto_secretbox_KEYBYTES);
	free(state->purported_receive_chain_key);

	free(state);
}

