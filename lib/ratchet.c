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
 * Helper function that checks if a buffer is <none>
 * (filled with zeroes), and does so without introducing
 * side channels, especially timing side channels.
 */
bool is_none(
		const unsigned char * const buffer,
		const size_t length) {
	//TODO: Find better implementation that
	//doesn't create an additional array. I don't
	//do that currently because I haven't enough
	//confidence that I'm not introducing any side
	//channels.

	//fill a buffer with zeroes
	unsigned char none[length];
	sodium_memzero(none, sizeof(none));

	return 0 == sodium_memcmp(none, buffer, sizeof(none));

}

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 *
 * The return value is a valid ratchet state or NULL if an error occured.
 */
ratchet_state* ratchet_create(
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		bool am_i_alice) {
	//check buffer sizes
	if ((our_private_identity->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (our_private_ephemeral->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
		return NULL;
	}
	ratchet_state *state = sodium_malloc(sizeof(ratchet_state));
	if (state == NULL) { //failed to allocate memory
		return NULL;
	}

	//initialize the buffers with the storage arrays
	buffer_init_with_pointer(&(state->root_key), (unsigned char*)state->root_key_storage, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_init_with_pointer(&(state->purported_root_key), (unsigned char*)state->purported_root_key_storage, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	//header keys
	buffer_init_with_pointer(&(state->send_header_key), (unsigned char*)state->send_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->receive_header_key), (unsigned char*)state->receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->next_send_header_key), (unsigned char*)state->next_send_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->next_receive_header_key), (unsigned char*)state->next_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->purported_receive_header_key), (unsigned char*)state->purported_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->purported_next_receive_header_key), (unsigned char*)state->purported_next_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//chain keys
	buffer_init_with_pointer(&(state->send_chain_key), (unsigned char*)state->send_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->receive_chain_key), (unsigned char*)state->receive_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->purported_receive_chain_key), (unsigned char*)state->purported_receive_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//identity keys
	buffer_init_with_pointer(&(state->our_public_identity), (unsigned char*)state->our_public_identity_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->their_public_identity), (unsigned char*)state->their_public_identity_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//ephemeral keys (ratchet keys)
	buffer_init_with_pointer(&(state->our_private_ephemeral), (unsigned char*)state->our_private_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->our_public_ephemeral), (unsigned char*)state->our_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->their_public_ephemeral), (unsigned char*)state->their_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(&(state->their_purported_public_ephemeral), (unsigned char*)state->their_purported_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

	//derive initial chain, root and header keys
	int status = derive_initial_root_chain_and_header_keys(
			&(state->root_key),
			&(state->send_chain_key),
			&(state->receive_chain_key),
			&(state->send_header_key),
			&(state->receive_header_key),
			&(state->next_send_header_key),
			&(state->next_receive_header_key),
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//copy keys into state
	//our public identity
	status = buffer_clone(&(state->our_public_identity), our_public_identity);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//their_public_identity
	status = buffer_clone(&(state->their_public_identity), their_public_identity);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//our_private_ephemeral
	status = buffer_clone(&(state->our_private_ephemeral), our_private_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//our_public_ephemeral
	status = buffer_clone(&(state->our_public_ephemeral), our_public_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//their_public_ephemeral
	status = buffer_clone(&(state->their_public_ephemeral), their_public_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}

	//initialise message keystore for skipped messages
	state->skipped_header_and_message_keys = header_and_message_keystore_init();
	state->purported_header_and_message_keys = header_and_message_keystore_init();

	//set other state
	state->am_i_alice = am_i_alice;
	state->ratchet_flag = am_i_alice;
	state->received_valid = true; //allowing the receival of new messages
	state->header_decryptable = NOT_TRIED;
	state->send_message_number = 0;
	state->receive_message_number = 0;
	state->previous_message_number = 0;

	return state;
}

/*
 * Create message and header keys to encrypt the next sent message with.
 */
int ratchet_next_send_keys(
		unsigned char * const next_message_key,
		unsigned char * const next_header_key,
		ratchet_state *state) {
	int status;
	if (state->ratchet_flag) {
		//generate new ephemeral key
		status = crypto_box_keypair(state->our_public_ephemeral.content, state->our_private_ephemeral.content);
		if (status != 0) {
			return status;
		}

		//HKs = NHKs (shift header keys)
		status = buffer_clone(&(state->send_header_key), &(state->next_send_header_key));
		if (status != 0) {
			return status;
		}

		//derive next root key and send chain key
		//RK, CKs, NHKs = HKDF(DH(DHs, DHr))
		buffer_t *previous_root_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
		status = buffer_clone(previous_root_key, &(state->root_key));
		if (status != 0) {
			buffer_clear(previous_root_key);
			return status;
		}
		status = derive_root_chain_and_header_keys(
				&(state->root_key),
				&(state->send_chain_key),
				&(state->next_send_header_key),
				&(state->our_private_ephemeral),
				&(state->our_public_ephemeral),
				&(state->their_public_ephemeral),
				previous_root_key,
				state->am_i_alice);
		buffer_clear(previous_root_key);
		if (status != 0) {
			return status;
		}

		state->previous_message_number = state->send_message_number;
		state->send_message_number = 0;
		state->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, 0x00)
	buffer_t *next_message_key_buffer = buffer_create_with_existing_array(next_message_key, crypto_secretbox_KEYBYTES); //FIXME remove this once ratchet.c is ported over to buffer_t
	status = derive_message_key(
			next_message_key_buffer,
			&(state->send_chain_key));
	if (status != 0) {
		return status;
	}

	//copy the header key
	memcpy(next_header_key, state->send_header_key.content, state->send_header_key.content_length);

	state->send_message_number++;

	//derive next chain key
	//CKs = HMAC-HASH(CKs, 0x01)
	buffer_t *old_chain_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = buffer_clone(old_chain_key, &(state->send_chain_key));
	if (status != 0) {
		buffer_clear(old_chain_key);
		return status;
	}
	status = derive_chain_key(
			&(state->send_chain_key),
			old_chain_key);
	buffer_clear(old_chain_key);

	return status;
}

/*
 * Get a copy of the current and the next receive header key.
 */
int ratchet_get_receive_header_keys(
		buffer_t * const current_receive_header_key,
		buffer_t * const next_receive_header_key,
		ratchet_state *state) {
	//check buffer sizes
	if ((current_receive_header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (next_receive_header_key->buffer_length < crypto_secretbox_KEYBYTES)) {
		return -6;
	}

	int status;
	//clone the header keys
	status = buffer_clone(current_receive_header_key, &(state->receive_header_key));
	if (status != 0) {
		buffer_clear(current_receive_header_key);
		return status;
	}
	status = buffer_clone(next_receive_header_key, &(state->next_receive_header_key));
	if (status != 0) {
		buffer_clear(current_receive_header_key);
		buffer_clear(next_receive_header_key);
		return status;
	}

	return 0;
}

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
int ratchet_set_header_decryptability(
		ratchet_header_decryptability header_decryptable,
		ratchet_state *state) {
	if ((state->header_decryptable != NOT_TRIED)) {
		//if the last message hasn't been properly handled yet, abort
		return -10;
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		return -10;
	}

	state->header_decryptable = header_decryptable;

	return 0;
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
int stage_skipped_header_and_message_keys(
		unsigned char * const purported_chain_key, //CKp
		unsigned char * const message_key, //MK
		const unsigned int purported_message_number,
		const unsigned char * const receive_chain_key,
		ratchet_state *state) {

	//if chain key is <none>, don't do anything
	if (is_none(receive_chain_key, crypto_secretbox_KEYBYTES)) {
		sodium_memzero(message_key, crypto_secretbox_KEYBYTES);
		sodium_memzero(purported_chain_key, crypto_secretbox_KEYBYTES);
		return 0;
	}

	//limit number of message keys to calculate
	static const unsigned int LIMIT = 100;
	if ((purported_message_number - state->receive_message_number) > LIMIT) {
		return -10;
	}

	int status;
	//copy current chain key to purported chain key
	buffer_t *purported_current_chain_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *purported_next_chain_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = buffer_clone_from_raw(purported_current_chain_key, receive_chain_key, purported_current_chain_key->content_length);
	if (status != 0) {
		buffer_clear(purported_current_chain_key);
		buffer_clear(purported_next_chain_key);
		return status;
	}

	//message key buffer
	buffer_t *message_key_buffer = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	//create all message keys
	unsigned int pos;
	for (pos = state->receive_message_number; pos <= purported_message_number; pos++) {
		status = derive_message_key(message_key_buffer, purported_current_chain_key);
		if (status != 0) {
			buffer_clear(purported_current_chain_key);
			buffer_clear(purported_next_chain_key);
			buffer_clear(message_key_buffer);
			return status;
		}

		//add message key to list of purported message keys
		if (pos < purported_message_number) { //only stage previous message keys
			status = header_and_message_keystore_add(
					&(state->purported_header_and_message_keys),
					message_key_buffer,
					&(state->receive_header_key));
			if (status != 0) {
				buffer_clear(purported_current_chain_key);
				buffer_clear(purported_next_chain_key);
				buffer_clear(message_key_buffer);
				return status;
			}
		} else { //current message key is not staged, but copied to return it's value
			status = buffer_clone_to_raw(message_key, message_key_buffer->content_length, message_key_buffer);
			if (status != 0) {
				buffer_clear(purported_next_chain_key);
				buffer_clear(purported_current_chain_key);
				buffer_clear(message_key_buffer);
				return status;
			}
		}
		buffer_clear(message_key_buffer);

		status = derive_chain_key(purported_next_chain_key, purported_current_chain_key);
		if (status != 0) {
			buffer_clear(purported_current_chain_key);
			buffer_clear(purported_next_chain_key);
			return status;
		}

		//shift chain keys
		status = buffer_clone(purported_current_chain_key, purported_next_chain_key);
		if (status != 0) {
			buffer_clear(purported_current_chain_key);
			buffer_clear(purported_next_chain_key);
			return status;
		}
	}

	//copy chain key to purported_receive_chain_key (this will be used in commit_skipped_header_and_message_keys)
	status = buffer_clone_to_raw(purported_chain_key, purported_next_chain_key->content_length, purported_next_chain_key);
	if (status != 0) {
		buffer_clear(purported_current_chain_key);
		buffer_clear(purported_next_chain_key);
		return status;
	}

	buffer_clear(purported_current_chain_key);
	buffer_clear(purported_next_chain_key);

	return 0;
}

/*
 * This corresponds to "commit_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Commit all the purported message keys into the message key store thats used
 * to actually decrypt late messages.
 */
int commit_skipped_header_and_message_keys(ratchet_state *state) {
	int status;
	//as long as the list of purported message keys isn't empty,
	//add them to the list of skipped message keys
	while (state->purported_header_and_message_keys.length != 0) {
		status = header_and_message_keystore_add(
				&(state->skipped_header_and_message_keys),
				&(state->purported_header_and_message_keys.head->message_key),
				&(state->purported_header_and_message_keys.head->header_key));
		if (status != 0) {
			return status;
		}
		header_and_message_keystore_remove(
				&(state->purported_header_and_message_keys),
				state->purported_header_and_message_keys.head);
	}
	return 0;
}

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
int ratchet_receive(
		unsigned char * const message_key,
		const unsigned char * const their_purported_public_ephemeral,
		const unsigned int purported_message_number,
		const unsigned int purported_previous_message_number,
		ratchet_state * const state) {
	if (!state->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		return -10;
	}

	//header decryption hasn't been tried yet
	if (state->header_decryptable == NOT_TRIED) {
		return -10;
	}

	int status;

	if ((!is_none(state->receive_header_key.content, crypto_aead_chacha20poly1305_KEYBYTES)) && (state->header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//copy purported message number
		state->purported_message_number = purported_message_number;

		//create skipped message keys and store current one
		status = stage_skipped_header_and_message_keys(
				state->purported_receive_chain_key.content,
				message_key,
				purported_message_number,
				state->receive_chain_key.content,
				state);
		if (status != 0) {
			return status;
		}

		//copy their purported public ephemeral (this is necessary to detect if a new chain was started later on when validating the authenticity)
		memcpy(state->their_purported_public_ephemeral.content, their_purported_public_ephemeral, crypto_box_PUBLICKEYBYTES);

		state->received_valid = false; //waiting for validation
		return 0;
	} else { //new message chain
		if ((state->ratchet_flag) || (state->header_decryptable != NEXT_DECRYPTABLE)) {
			return -10;
		}

		//copy purported message numbers and ephemerals
		state->purported_message_number = purported_message_number; //Np
		state->purported_previous_message_number = purported_previous_message_number; //PNp
		memcpy(state->their_purported_public_ephemeral.content, their_purported_public_ephemeral, crypto_box_PUBLICKEYBYTES); //DHRp

		//temporary storage for the purported chain key (CKp)
		unsigned char temp_purported_chain_key[crypto_secretbox_KEYBYTES];

		//stage message keys for previous message chain
		status = stage_skipped_header_and_message_keys(
				temp_purported_chain_key,
				message_key,
				purported_previous_message_number,
				state->receive_chain_key.content,
				state);
		if (status != 0) {
			sodium_memzero(temp_purported_chain_key, sizeof(temp_purported_chain_key));
			return status;
		}

		//HKp = NHKr
		status = buffer_clone(&(state->purported_receive_header_key), &(state->next_receive_header_key));
		if (status != 0) {
			sodium_memzero(temp_purported_chain_key, sizeof(temp_purported_chain_key));
			return status;
		}

		//create buffers FIXME remove this once ratchet.c is ported over to buffer_t
		buffer_t *their_purported_public_ephemeral_buffer = buffer_create_with_existing_array((unsigned char*)their_purported_public_ephemeral, crypto_box_PUBLICKEYBYTES);

		//derive purported root and chain keys
		//first: input key for hkdf (root and chain key derivation)
		status = derive_root_chain_and_header_keys(
				&(state->purported_root_key),
				&(state->purported_receive_chain_key),
				&(state->purported_next_receive_header_key),
				&(state->our_private_ephemeral),
				&(state->our_public_ephemeral),
				their_purported_public_ephemeral_buffer,
				&(state->root_key),
				state->am_i_alice);
		if (status != 0) {
			return status;
		}

		//stage message keys for current message chain
		status = stage_skipped_header_and_message_keys(
				temp_purported_chain_key,
				message_key,
				purported_message_number,
				state->purported_receive_chain_key.content,
				state);
		if (status != 0) {
			sodium_memzero(temp_purported_chain_key, sizeof(temp_purported_chain_key));
			return status;
		}

		//copy the temporary purported chain key to the state
		memcpy(state->purported_receive_chain_key.content, temp_purported_chain_key, state->purported_receive_chain_key.content_length);

		state->received_valid = false; //waiting for validation
	}

	return 0;
}

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
int ratchet_set_last_message_authenticity(ratchet_state *state, bool valid) {
	//prepare for being able to receive new messages
	state->received_valid = true;

	//backup header decryptability
	ratchet_header_decryptability header_decryptable = state->header_decryptable;
	state->header_decryptable = NOT_TRIED;

	//TODO make sure this function aborts if it is called at the wrong time

	int status;

	//TODO I can do those if's better. This only happens to be this way because of the specification
	if ((!is_none(state->receive_header_key.content, crypto_aead_chacha20poly1305_KEYBYTES)) && (header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//if HKr != <none> and Dec(HKr, header)
		if (!valid) { //message couldn't be decrypted
			//clear purported message and header keys
			header_and_message_keystore_clear(&(state->purported_header_and_message_keys));
			return 0; //TODO: Should this really be 0?
		}
	} else { //new message chain
		if (state->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE) || !valid) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			header_and_message_keystore_clear(&(state->purported_header_and_message_keys));
			return 0; //TODO: Should this really be 0?
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		status = buffer_clone(&(state->root_key), &(state->purported_root_key));
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//HKr = HKp
		status = buffer_clone(&(state->receive_header_key), &(state->purported_receive_header_key));
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//NHKr = NHKp
		status = buffer_clone(&(state->next_receive_header_key), &(state->purported_next_receive_header_key));
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//DHRr = DHRp
		status = buffer_clone(&(state->their_public_ephemeral), &(state->their_purported_public_ephemeral));
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//erase(DHRs)
		buffer_clear(&(state->our_private_ephemeral));
		state->our_private_ephemeral.content_length = crypto_box_SECRETKEYBYTES; //TODO is this necessary?
		//ratchet_flag = True
		state->ratchet_flag = true;
	}

	status = commit_skipped_header_and_message_keys(state);
	if (status != 0) {
		return status;
	}
	//Nr = Np + 1
	state->receive_message_number = state->purported_message_number + 1;
	//CKr = CKp
	status = buffer_clone(&(state->receive_chain_key), &(state->purported_receive_chain_key));
	if (status != 0) {
		//TODO what to clear here?
		return status;
	}

	return 0;
}

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state) {
	//empty message keystores
	header_and_message_keystore_clear(&(state->skipped_header_and_message_keys));
	header_and_message_keystore_clear(&(state->purported_header_and_message_keys));

	sodium_free(state); //this also overwrites all the keys with zeroes
}

