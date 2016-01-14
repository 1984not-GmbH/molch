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
bool is_none(const buffer_t * const buffer) {
	return sodium_is_zero(buffer->content, buffer->content_length);
}

/*
 * Create a new ratchet_state and initialise the pointers.
 */
ratchet_state *create_ratchet_state() {
	ratchet_state *state = sodium_malloc(sizeof(ratchet_state));
	if (state == NULL) { //failed to allocate memory
		return NULL;
	}

	//initialize the buffers with the storage arrays
	buffer_init_with_pointer(state->root_key, (unsigned char*)state->root_key_storage, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_init_with_pointer(state->purported_root_key, (unsigned char*)state->purported_root_key_storage, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	//header keys
	buffer_init_with_pointer(state->send_header_key, (unsigned char*)state->send_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->receive_header_key, (unsigned char*)state->receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->next_send_header_key, (unsigned char*)state->next_send_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->next_receive_header_key, (unsigned char*)state->next_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->purported_receive_header_key, (unsigned char*)state->purported_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->purported_next_receive_header_key, (unsigned char*)state->purported_next_receive_header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//chain keys
	buffer_init_with_pointer(state->send_chain_key, (unsigned char*)state->send_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->receive_chain_key, (unsigned char*)state->receive_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->purported_receive_chain_key, (unsigned char*)state->purported_receive_chain_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//identity keys
	buffer_init_with_pointer(state->our_public_identity, (unsigned char*)state->our_public_identity_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->their_public_identity, (unsigned char*)state->their_public_identity_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//ephemeral keys (ratchet keys)
	buffer_init_with_pointer(state->our_private_ephemeral, (unsigned char*)state->our_private_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->our_public_ephemeral, (unsigned char*)state->our_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->their_public_ephemeral, (unsigned char*)state->their_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_init_with_pointer(state->their_purported_public_ephemeral, (unsigned char*)state->their_purported_public_ephemeral_storage, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

	//initialise message keystore for skipped messages
	header_and_message_keystore_init(state->skipped_header_and_message_keys);
	header_and_message_keystore_init(state->purported_header_and_message_keys);

	return state;
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
		const buffer_t * const their_public_ephemeral) {
	//check buffer sizes
	if ((our_private_identity->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (our_private_ephemeral->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
		return NULL;
	}

	ratchet_state *state = create_ratchet_state();
	if (state == NULL) {
		return NULL;
	}

	//find out if we are alice by comparing both public keys
	//the one with the bigger public key is alice
	int comparison = memcmp(our_public_identity->content, their_public_identity->content, our_public_identity->content_length);
	if (comparison > 0) {
		state->am_i_alice = true;
	} else if (comparison < 0) {
		state->am_i_alice = false;
	} else {
		assert(false && "This mustn't happen, both conversation partners have the same public key!");
	}

	//derive initial chain, root and header keys
	int status = derive_initial_root_chain_and_header_keys(
			state->root_key,
			state->send_chain_key,
			state->receive_chain_key,
			state->send_header_key,
			state->receive_header_key,
			state->next_send_header_key,
			state->next_receive_header_key,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			state->am_i_alice);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//copy keys into state
	//our public identity
	status = buffer_clone(state->our_public_identity, our_public_identity);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//their_public_identity
	status = buffer_clone(state->their_public_identity, their_public_identity);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//our_private_ephemeral
	status = buffer_clone(state->our_private_ephemeral, our_private_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//our_public_ephemeral
	status = buffer_clone(state->our_public_ephemeral, our_public_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}
	//their_public_ephemeral
	status = buffer_clone(state->their_public_ephemeral, their_public_ephemeral);
	if (status != 0) {
		sodium_free(state);
		return NULL;
	}

	//set other state
	state->ratchet_flag = state->am_i_alice;
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
		buffer_t * const next_message_key,
		buffer_t * const next_header_key,
		ratchet_state *state) {
	int status;
	if (state->ratchet_flag) {
		//generate new ephemeral key
		status = crypto_box_keypair(state->our_public_ephemeral->content, state->our_private_ephemeral->content);
		if (status != 0) {
			return status;
		}

		//HKs = NHKs (shift header keys)
		status = buffer_clone(state->send_header_key, state->next_send_header_key);
		if (status != 0) {
			return status;
		}

		//derive next root key and send chain key
		//RK, CKs, NHKs = HKDF(DH(DHs, DHr))
		buffer_t *previous_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
		status = buffer_clone(previous_root_key, state->root_key);
		if (status != 0) {
			buffer_destroy_from_heap(previous_root_key);
			return status;
		}
		status = derive_root_chain_and_header_keys(
				state->root_key,
				state->send_chain_key,
				state->next_send_header_key,
				state->our_private_ephemeral,
				state->our_public_ephemeral,
				state->their_public_ephemeral,
				previous_root_key,
				state->am_i_alice);
		buffer_destroy_from_heap(previous_root_key);
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
		buffer_clear(next_message_key);
		return status;
	}

	//copy the header key
	status = buffer_clone(next_header_key, state->send_header_key);
	if (status != 0) {
		buffer_clear(next_message_key);
		buffer_clear(next_header_key);
		return status;
	}

	state->send_message_number++;

	//derive next chain key
	//CKs = HMAC-HASH(CKs, 0x01)
	buffer_t *old_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = buffer_clone(old_chain_key, state->send_chain_key);
	if (status != 0) {
		buffer_destroy_from_heap(old_chain_key);
		buffer_clear(next_header_key);
		buffer_clear(next_message_key);
		return status;
	}
	status = derive_chain_key(
			state->send_chain_key,
			old_chain_key);
	if (status != 0) {
		buffer_destroy_from_heap(old_chain_key);
		buffer_clear(next_message_key);
		buffer_clear(next_header_key);
		return status;
	}
	buffer_destroy_from_heap(old_chain_key);

	return 0;
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
	status = buffer_clone(current_receive_header_key, state->receive_header_key);
	if (status != 0) {
		buffer_clear(current_receive_header_key);
		return status;
	}
	status = buffer_clone(next_receive_header_key, state->next_receive_header_key);
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
		buffer_t * const purported_chain_key, //CKp
		buffer_t * const message_key, //MK
		const unsigned int purported_message_number,
		const buffer_t * const receive_chain_key,
		ratchet_state *state) {
	if ((purported_chain_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (message_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (receive_chain_key->content_length != crypto_secretbox_KEYBYTES)) {
		buffer_clear(message_key);
		buffer_clear(purported_chain_key);
		return -6;
	}

	//if chain key is <none>, don't do anything
	if (is_none(receive_chain_key)) {
		buffer_clear(message_key);
		buffer_clear(purported_chain_key);
		return 0;
	}

	//limit number of message keys to calculate
	static const unsigned int LIMIT = 100;
	if ((purported_message_number - state->receive_message_number) > LIMIT) {
		return -10;
	}

	int status;
	//message key buffer
	buffer_t *message_key_buffer = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	//copy current chain key to purported chain key
	buffer_t *purported_current_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *purported_next_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = buffer_clone(purported_current_chain_key, receive_chain_key);
	if (status != 0) {
		goto cleanup;
	}


	//create all message keys
	unsigned int pos;
	for (pos = state->receive_message_number; pos <= purported_message_number; pos++) {
		status = derive_message_key(message_key_buffer, purported_current_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//add message key to list of purported message keys
		if (pos < purported_message_number) { //only stage previous message keys
			status = header_and_message_keystore_add(
					state->purported_header_and_message_keys,
					message_key_buffer,
					state->receive_header_key);
			if (status != 0) {
				goto cleanup;
			}
		} else { //current message key is not staged, but copied to return it's value
			status = buffer_clone(message_key, message_key_buffer);
			if (status != 0) {
				goto cleanup;
			}
		}

		status = derive_chain_key(purported_next_chain_key, purported_current_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//shift chain keys
		status = buffer_clone(purported_current_chain_key, purported_next_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	}

	//copy chain key to purported_receive_chain_key (this will be used in commit_skipped_header_and_message_keys)
	status = buffer_clone(purported_chain_key, purported_next_chain_key);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(purported_current_chain_key);
	buffer_destroy_from_heap(purported_next_chain_key);
	buffer_destroy_from_heap(message_key_buffer);

	return status;
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
	while (state->purported_header_and_message_keys->length != 0) {
		status = header_and_message_keystore_add(
				state->skipped_header_and_message_keys,
				state->purported_header_and_message_keys->head->message_key,
				state->purported_header_and_message_keys->head->header_key);
		if (status != 0) {
			return status;
		}
		header_and_message_keystore_remove(
				state->purported_header_and_message_keys,
				state->purported_header_and_message_keys->head);
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
		buffer_t * const message_key,
		const buffer_t * const their_purported_public_ephemeral,
		const unsigned int purported_message_number,
		const unsigned int purported_previous_message_number,
		ratchet_state * const state) {
	//check buffer sizes
	if ((message_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (their_purported_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
		return -6;
	}

	if (!state->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		return -10;
	}

	//header decryption hasn't been tried yet
	if (state->header_decryptable == NOT_TRIED) {
		return -10;
	}

	int status;

	if ((!is_none(state->receive_header_key)) && (state->header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//copy purported message number
		state->purported_message_number = purported_message_number;

		//create skipped message keys and store current one
		status = stage_skipped_header_and_message_keys(
				state->purported_receive_chain_key,
				message_key,
				purported_message_number,
				state->receive_chain_key,
				state);
		if (status != 0) {
			return status;
		}

		//copy their purported public ephemeral (this is necessary to detect if a new chain was started later on when validating the authenticity)
		status = buffer_clone(state->their_purported_public_ephemeral, their_purported_public_ephemeral);
		if (status != 0) {
			return status;
		}

		state->received_valid = false; //waiting for validation
		return 0;
	} else { //new message chain
		if ((state->ratchet_flag) || (state->header_decryptable != NEXT_DECRYPTABLE)) {
			return -10;
		}

		//copy purported message numbers and ephemerals
		state->purported_message_number = purported_message_number; //Np
		state->purported_previous_message_number = purported_previous_message_number; //PNp
		status = buffer_clone(state->their_purported_public_ephemeral, their_purported_public_ephemeral);
		if (status != 0) {
			return status;
		}

		//temporary storage for the purported chain key (CKp)
		buffer_t *temp_purported_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

		//stage message keys for previous message chain
		status = stage_skipped_header_and_message_keys(
				temp_purported_chain_key,
				message_key,
				purported_previous_message_number,
				state->receive_chain_key,
				state);
		if (status != 0) {
			buffer_destroy_from_heap(temp_purported_chain_key);
			return status;
		}

		//HKp = NHKr
		status = buffer_clone(state->purported_receive_header_key, state->next_receive_header_key);
		if (status != 0) {
			buffer_destroy_from_heap(temp_purported_chain_key);
			return status;
		}

		//derive purported root and chain keys
		//first: input key for hkdf (root and chain key derivation)
		status = derive_root_chain_and_header_keys(
				state->purported_root_key,
				state->purported_receive_chain_key,
				state->purported_next_receive_header_key,
				state->our_private_ephemeral,
				state->our_public_ephemeral,
				their_purported_public_ephemeral,
				state->root_key,
				state->am_i_alice);
		if (status != 0) {
			return status;
		}

		//stage message keys for current message chain
		status = stage_skipped_header_and_message_keys(
				temp_purported_chain_key,
				message_key,
				purported_message_number,
				state->purported_receive_chain_key,
				state);
		if (status != 0) {
			buffer_destroy_from_heap(temp_purported_chain_key);
			return status;
		}

		//copy the temporary purported chain key to the state
		status = buffer_clone(state->purported_receive_chain_key, temp_purported_chain_key);
		buffer_destroy_from_heap(temp_purported_chain_key);
		if (status != 0) {
			return status;
		}

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
	if ((!is_none(state->receive_header_key)) && (header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//if HKr != <none> and Dec(HKr, header)
		if (!valid) { //message couldn't be decrypted
			//clear purported message and header keys
			header_and_message_keystore_clear(state->purported_header_and_message_keys);
			return 0; //TODO: Should this really be 0?
		}
	} else { //new message chain
		if (state->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE) || !valid) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			header_and_message_keystore_clear(state->purported_header_and_message_keys);
			return 0; //TODO: Should this really be 0?
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		status = buffer_clone(state->root_key, state->purported_root_key);
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//HKr = HKp
		status = buffer_clone(state->receive_header_key, state->purported_receive_header_key);
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//NHKr = NHKp
		status = buffer_clone(state->next_receive_header_key, state->purported_next_receive_header_key);
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//DHRr = DHRp
		status = buffer_clone(state->their_public_ephemeral, state->their_purported_public_ephemeral);
		if (status != 0) {
			//TODO what to clear here?
			return status;
		}
		//erase(DHRs)
		buffer_clear(state->our_private_ephemeral);
		state->our_private_ephemeral->content_length = crypto_box_SECRETKEYBYTES; //TODO is this necessary?
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
	status = buffer_clone(state->receive_chain_key, state->purported_receive_chain_key);
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
	header_and_message_keystore_clear(state->skipped_header_and_message_keys);
	header_and_message_keystore_clear(state->purported_header_and_message_keys);

	sodium_free(state); //this also overwrites all the keys with zeroes
}

/*
 * Serialise a ratchet into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *ratchet_json_export(const ratchet_state * const state, mempool_t * const pool) {
	if ((state == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//export the root keys
	mcJSON *root_key = mcJSON_CreateHexString(state->root_key, pool);
	mcJSON *purported_root_key = mcJSON_CreateHexString(state->purported_root_key, pool);
	mcJSON *root_keys = mcJSON_CreateObject(pool);
	if ((root_key == NULL) || (purported_root_key == NULL) || (root_keys == NULL)) {
		return NULL;
	}
	buffer_create_from_string(root_key_string, "root_key");
	mcJSON_AddItemToObject(root_keys, root_key_string, root_key, pool);
	buffer_create_from_string(purported_root_key_string, "purported_root_key");
	mcJSON_AddItemToObject(root_keys, purported_root_key_string, purported_root_key, pool);
	buffer_create_from_string(root_keys_string, "root_keys");
	mcJSON_AddItemToObject(json, root_keys_string, root_keys, pool);

	//export header keys
	mcJSON *send_header_key = mcJSON_CreateHexString(state->send_header_key, pool);
	mcJSON *receive_header_key = mcJSON_CreateHexString(state->receive_header_key, pool);
	mcJSON *next_send_header_key = mcJSON_CreateHexString(state->next_send_header_key, pool);
	mcJSON *next_receive_header_key = mcJSON_CreateHexString(state->next_receive_header_key, pool);
	mcJSON *purported_receive_header_key = mcJSON_CreateHexString(state->purported_receive_header_key, pool);
	mcJSON *purported_next_receive_header_key = mcJSON_CreateHexString(state->purported_next_receive_header_key, pool);
	mcJSON *header_keys = mcJSON_CreateObject(pool);
	if ((send_header_key == NULL) || (receive_header_key == NULL) || (next_send_header_key == NULL) || (next_receive_header_key == NULL) || (purported_receive_header_key == NULL) || (purported_next_receive_header_key == NULL) || (header_keys == NULL)) {
		return NULL;
	}
	buffer_create_from_string(send_header_key_string, "send_header_key");
	mcJSON_AddItemToObject(header_keys, send_header_key_string, send_header_key, pool);
	buffer_create_from_string(receive_header_key_string, "receive_header_key");
	mcJSON_AddItemToObject(header_keys, receive_header_key_string, receive_header_key, pool);
	buffer_create_from_string(next_send_header_key_string, "next_send_header_key");
	mcJSON_AddItemToObject(header_keys, next_send_header_key_string, next_send_header_key, pool);
	buffer_create_from_string(next_receive_header_key_string, "next_receive_header_key");
	mcJSON_AddItemToObject(header_keys, next_receive_header_key_string, next_receive_header_key, pool);
	buffer_create_from_string(purported_receive_header_key_string, "purported_receive_header_key");
	mcJSON_AddItemToObject(header_keys, purported_receive_header_key_string, purported_receive_header_key, pool);
	buffer_create_from_string(purported_next_receive_header_key_string, "purported_next_receive_header_key");
	mcJSON_AddItemToObject(header_keys, purported_next_receive_header_key_string, purported_next_receive_header_key, pool);
	buffer_create_from_string(header_keys_string, "header_keys");
	mcJSON_AddItemToObject(json, header_keys_string, header_keys, pool);

	//export chain keys
	mcJSON *send_chain_key = mcJSON_CreateHexString(state->send_chain_key, pool);
	mcJSON *receive_chain_key = mcJSON_CreateHexString(state->receive_chain_key, pool);
	mcJSON *purported_receive_chain_key = mcJSON_CreateHexString(state->receive_chain_key, pool);
	mcJSON *chain_keys = mcJSON_CreateObject(pool);
	if ((send_chain_key == NULL) || (receive_chain_key == NULL) || (purported_receive_chain_key == NULL) || (chain_keys == NULL)) {
		return NULL;
	}
	buffer_create_from_string(send_chain_key_string, "send_chain_key");
	mcJSON_AddItemToObject(chain_keys, send_chain_key_string, send_chain_key, pool);
	buffer_create_from_string(receive_chain_key_string, "receive_chain_key");
	mcJSON_AddItemToObject(chain_keys, receive_chain_key_string, receive_chain_key, pool);
	buffer_create_from_string(purported_receive_chain_key_string, "purported_receive_chain_key");
	mcJSON_AddItemToObject(chain_keys, purported_receive_chain_key_string, purported_receive_chain_key, pool);
	buffer_create_from_string(chain_keys_string, "chain_keys");
	mcJSON_AddItemToObject(json, chain_keys_string, chain_keys, pool);

	//export our keys
	mcJSON *our_public_identity = mcJSON_CreateHexString(state->our_public_identity, pool);
	mcJSON *our_public_ephemeral = mcJSON_CreateHexString(state->our_public_ephemeral, pool);
	mcJSON *our_private_ephemeral = mcJSON_CreateHexString(state->our_private_ephemeral, pool);
	mcJSON *our_keys = mcJSON_CreateObject(pool);
	if ((our_public_identity == NULL) || (our_public_ephemeral == NULL) || (our_private_ephemeral == NULL) || (our_keys == NULL)) {
		return NULL;
	}
	buffer_create_from_string(public_identity_string, "public_identity");
	mcJSON_AddItemToObject(our_keys, public_identity_string, our_public_identity, pool);
	buffer_create_from_string(public_ephemeral_string, "public_ephemeral");
	mcJSON_AddItemToObject(our_keys, public_ephemeral_string, our_public_ephemeral, pool);
	buffer_create_from_string(private_ephemeral_string, "private_ephemeral");
	mcJSON_AddItemToObject(our_keys, private_ephemeral_string, our_private_ephemeral, pool);
	buffer_create_from_string(our_keys_string, "our_keys");
	mcJSON_AddItemToObject(json, our_keys_string, our_keys, pool);

	//export their keys
	mcJSON *their_public_identity = mcJSON_CreateHexString(state->their_public_identity, pool);
	mcJSON *their_public_ephemeral = mcJSON_CreateHexString(state->their_public_ephemeral, pool);
	mcJSON *their_purported_public_ephemeral = mcJSON_CreateHexString(state->their_purported_public_ephemeral, pool);
	mcJSON *their_keys = mcJSON_CreateObject(pool);
	if ((their_public_identity == NULL) || (their_public_ephemeral == NULL) || (their_purported_public_ephemeral == NULL) || (their_keys == NULL)) {
		return NULL;
	}
	mcJSON_AddItemToObject(their_keys, public_identity_string, their_public_identity, pool);
	mcJSON_AddItemToObject(their_keys, public_ephemeral_string, their_public_ephemeral, pool);
	buffer_create_from_string(purported_public_ephemeral_string, "purported_public_ephemeral");
	mcJSON_AddItemToObject(their_keys, purported_public_ephemeral_string, their_purported_public_ephemeral, pool);
	buffer_create_from_string(their_keys_string, "their_keys");
	mcJSON_AddItemToObject(json, their_keys_string, their_keys, pool);

	//export message numbers
	mcJSON *send_message_number = mcJSON_CreateNumber(state->send_message_number, pool);
	mcJSON *receive_message_number = mcJSON_CreateNumber(state->receive_message_number, pool);
	mcJSON *purported_message_number = mcJSON_CreateNumber(state->purported_message_number, pool);
	mcJSON *previous_message_number = mcJSON_CreateNumber(state->previous_message_number, pool);
	mcJSON *purported_previous_message_number = mcJSON_CreateNumber(state->purported_previous_message_number, pool);
	mcJSON *message_numbers = mcJSON_CreateObject(pool);
	if ((send_message_number == NULL) || (receive_message_number == NULL) || (purported_message_number == NULL) || (previous_message_number == NULL) || (purported_previous_message_number == NULL) || (message_numbers == NULL)) {
		return NULL;
	}
	buffer_create_from_string(send_message_number_string, "send_message_number");
	mcJSON_AddItemToObject(message_numbers, send_message_number_string, send_message_number, pool);
	buffer_create_from_string(receive_message_number_string, "receive_message_number");
	mcJSON_AddItemToObject(message_numbers, receive_message_number_string, receive_message_number, pool);
	buffer_create_from_string(previous_message_number_string, "previous_message_number");
	mcJSON_AddItemToObject(message_numbers, previous_message_number_string, previous_message_number, pool);
	buffer_create_from_string(purported_message_number_string, "purported_message_number");
	mcJSON_AddItemToObject(message_numbers, purported_message_number_string, purported_message_number, pool);
	buffer_create_from_string(purported_previous_message_number_string, "purported_previous_message_number");
	mcJSON_AddItemToObject(message_numbers, purported_previous_message_number_string, purported_previous_message_number, pool);
	buffer_create_from_string(message_numbers_string, "message_numbers");
	mcJSON_AddItemToObject(json, message_numbers_string, message_numbers, pool);

	//export other data
	mcJSON *ratchet_flag = mcJSON_CreateBool(state->ratchet_flag, pool);
	mcJSON *am_i_alice = mcJSON_CreateBool(state->am_i_alice, pool);
	mcJSON *received_valid = mcJSON_CreateBool(state->received_valid, pool);
	mcJSON *header_decryptable = mcJSON_CreateNumber(state->header_decryptable, pool);
	if ((ratchet_flag == NULL) || (am_i_alice == NULL) || (received_valid == NULL) || (header_decryptable == NULL)) {
		return NULL;
	}
	buffer_create_from_string(ratchet_flag_string, "ratchet_flag");
	mcJSON_AddItemToObject(json, ratchet_flag_string, ratchet_flag, pool);
	buffer_create_from_string(am_i_alice_string, "am_i_alice");
	mcJSON_AddItemToObject(json, am_i_alice_string, am_i_alice, pool);
	buffer_create_from_string(received_valid_string, "received_valid");
	mcJSON_AddItemToObject(json, received_valid_string, received_valid, pool);
	buffer_create_from_string(header_decryptable_string, "header_decryptable");
	mcJSON_AddItemToObject(json, header_decryptable_string, header_decryptable, pool);

	//export header and message keystores
	mcJSON *skipped_header_and_message_keys = header_and_message_keystore_json_export((header_and_message_keystore * const) &(state->skipped_header_and_message_keys), pool);
	mcJSON *purported_header_and_message_keys = header_and_message_keystore_json_export((header_and_message_keystore * const ) &(state->purported_header_and_message_keys), pool);
	mcJSON *keystores = mcJSON_CreateObject(pool);
	if ((skipped_header_and_message_keys == NULL) || (purported_header_and_message_keys == NULL) || (keystores == NULL)) {
		return NULL;
	}
	buffer_create_from_string(skipped_header_and_message_keys_string, "skipped_header_and_message_keys");
	mcJSON_AddItemToObject(keystores, skipped_header_and_message_keys_string, skipped_header_and_message_keys, pool);
	buffer_create_from_string(purported_header_and_message_keys_string, "purported_header_and_message_keys");
	mcJSON_AddItemToObject(keystores, purported_header_and_message_keys_string, purported_header_and_message_keys, pool);
	buffer_create_from_string(header_and_message_keystores_string, "header_and_message_keystores");
	mcJSON_AddItemToObject(json, header_and_message_keystores_string, keystores, pool);

	return json;
}

/*
 * Deserialise a ratchet (import from JSON).
 */
ratchet_state *ratchet_json_import(const mcJSON * const json) {
	if (json == NULL) {
		return NULL;
	}

	ratchet_state *state = create_ratchet_state();
	if (state == NULL) {
		return NULL;
	}

	if (json->type != mcJSON_Object) {
		goto fail;
	}

	//import root keys
	//get from json
	buffer_create_from_string(root_keys_string, "root_keys");
	mcJSON *root_keys = mcJSON_GetObjectItem(json, root_keys_string);
	if ((root_keys == NULL) || (root_keys->type != mcJSON_Object)) {
		goto fail;
	}

	buffer_create_from_string(root_key_string, "root_key");
	mcJSON *root_key = mcJSON_GetObjectItem(root_keys, root_key_string);
	buffer_create_from_string(purported_root_key_string, "purported_root_key");
	mcJSON *purported_root_key = mcJSON_GetObjectItem(root_keys, purported_root_key_string);
	if ((root_key == NULL) || (root_key->type != mcJSON_String) || (root_key->valuestring->content_length != (2 * crypto_secretbox_KEYBYTES + 1))
			|| (purported_root_key == NULL) || (purported_root_key->type != mcJSON_String) || (purported_root_key->valuestring->content_length != (2 * crypto_secretbox_KEYBYTES + 1))) {
		goto fail;
	}

	//copy to state
	if (buffer_clone_from_hex(state->root_key, root_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->purported_root_key, purported_root_key->valuestring) != 0) {
		goto fail;
	}

	//import header keys
	//get from json
	buffer_create_from_string(header_keys_string, "header_keys");
	mcJSON *header_keys = mcJSON_GetObjectItem(json, header_keys_string);
	if ((header_keys == NULL) || (header_keys->type != mcJSON_Object)) {
		goto fail;
	}

	buffer_create_from_string(send_header_key_string, "send_header_key");
	mcJSON *send_header_key = mcJSON_GetObjectItem(header_keys, send_header_key_string);
	buffer_create_from_string(receive_header_key_string, "receive_header_key");
	mcJSON *receive_header_key = mcJSON_GetObjectItem(header_keys, receive_header_key_string);
	buffer_create_from_string(next_send_header_key_string, "next_send_header_key");
	mcJSON *next_send_header_key = mcJSON_GetObjectItem(header_keys, next_send_header_key_string);
	buffer_create_from_string(next_receive_header_key_string, "next_receive_header_key");
	mcJSON *next_receive_header_key = mcJSON_GetObjectItem(header_keys, next_receive_header_key_string);
	buffer_create_from_string(purported_receive_header_key_string, "purported_receive_header_key");
	mcJSON *purported_receive_header_key = mcJSON_GetObjectItem(header_keys, purported_receive_header_key_string);
	buffer_create_from_string(purported_next_receive_header_key_string, "purported_next_receive_header_key");
	mcJSON *purported_next_receive_header_key = mcJSON_GetObjectItem(header_keys, purported_next_receive_header_key_string);
	if ((send_header_key == NULL) || (send_header_key->type != mcJSON_String) || (send_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))
			|| (receive_header_key == NULL) || (receive_header_key->type != mcJSON_String) || (receive_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))
			|| (next_send_header_key == NULL) || (next_send_header_key->type != mcJSON_String) || (next_send_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))
			|| (next_receive_header_key == NULL) || (next_receive_header_key->type != mcJSON_String) || (next_receive_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))
			|| (purported_receive_header_key == NULL) || (purported_receive_header_key->type != mcJSON_String) || (purported_receive_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))
			|| (purported_next_receive_header_key == NULL) || (purported_next_receive_header_key->type != mcJSON_String) || (purported_next_receive_header_key->valuestring->content_length != (2 * crypto_aead_chacha20poly1305_KEYBYTES + 1))) {
		goto fail;
	}

	//copy to state
	if (buffer_clone_from_hex(state->send_header_key, send_header_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->receive_header_key, receive_header_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->next_send_header_key, next_send_header_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->next_receive_header_key, next_receive_header_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->purported_receive_header_key, purported_receive_header_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->purported_next_receive_header_key, purported_next_receive_header_key->valuestring) != 0) {
		goto fail;
	}

	//import chain keys
	//get from json
	buffer_create_from_string(chain_keys_string, "chain_keys");
	mcJSON *chain_keys = mcJSON_GetObjectItem(json, chain_keys_string);
	if ((chain_keys == NULL) || (chain_keys->type != mcJSON_Object)) {
		goto fail;
	}
	buffer_create_from_string(send_chain_key_string, "send_chain_key");
	mcJSON *send_chain_key = mcJSON_GetObjectItem(chain_keys, send_chain_key_string);
	buffer_create_from_string(receive_chain_key_string, "receive_chain_key");
	mcJSON *receive_chain_key = mcJSON_GetObjectItem(chain_keys, receive_chain_key_string);
	buffer_create_from_string(purported_receive_chain_key_string, "purported_receive_chain_key");
	mcJSON *purported_receive_chain_key = mcJSON_GetObjectItem(chain_keys, purported_receive_chain_key_string);
	if ((send_chain_key == NULL) || (send_chain_key->type != mcJSON_String) || (send_chain_key->valuestring->content_length != (2 * crypto_secretbox_KEYBYTES + 1))
			|| (receive_chain_key == NULL) || (receive_chain_key->type != mcJSON_String) || (receive_chain_key->valuestring->content_length != (2 * crypto_secretbox_KEYBYTES + 1))
			|| (purported_receive_chain_key == NULL) || (purported_receive_chain_key->type != mcJSON_String) || (purported_receive_chain_key->valuestring->content_length != (2 * crypto_secretbox_KEYBYTES + 1))) {
			goto fail;
	}

	//copy to state
	if (buffer_clone_from_hex(state->send_chain_key, send_chain_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->receive_chain_key, receive_chain_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->purported_receive_chain_key, purported_receive_chain_key->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->purported_next_receive_header_key, purported_next_receive_header_key->valuestring) != 0) {
		goto fail;
	}

	//import our keys
	//get from json
	buffer_create_from_string(our_keys_string, "our_keys");
	mcJSON *our_keys = mcJSON_GetObjectItem(json, our_keys_string);
	if ((our_keys == NULL) || (our_keys->type != mcJSON_Object)) {
		goto fail;
	}
	buffer_create_from_string(public_identity_string, "public_identity");
	mcJSON *our_public_identity = mcJSON_GetObjectItem(our_keys, public_identity_string);
	buffer_create_from_string(public_ephemeral_string, "public_ephemeral");
	mcJSON *our_public_ephemeral = mcJSON_GetObjectItem(our_keys, public_ephemeral_string);
	buffer_create_from_string(private_ephemeral_string, "private_ephemeral");
	mcJSON *our_private_ephemeral = mcJSON_GetObjectItem(our_keys, private_ephemeral_string);
	if ((our_public_identity == NULL) || (our_public_identity->type != mcJSON_String) || (our_public_identity->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->type != mcJSON_String) || (our_public_ephemeral->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))
			|| (our_private_ephemeral == NULL) || (our_private_ephemeral->type != mcJSON_String) || (our_private_ephemeral->valuestring->content_length != (2 * crypto_box_SECRETKEYBYTES + 1))) {
		goto fail;
	}

	//copy to state
	if (buffer_clone_from_hex(state->our_public_identity, our_public_identity->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->our_public_ephemeral, our_public_ephemeral->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->our_private_ephemeral, our_private_ephemeral->valuestring) != 0) {
		goto fail;
	}

	//import their keys
	//get from json
	buffer_create_from_string(their_keys_string, "their_keys");
	mcJSON *their_keys = mcJSON_GetObjectItem(json, their_keys_string);
	if ((their_keys == NULL) || (their_keys->type != mcJSON_Object)) {
		goto fail;
	}
	mcJSON *their_public_identity = mcJSON_GetObjectItem(their_keys, public_identity_string);
	mcJSON *their_public_ephemeral = mcJSON_GetObjectItem(their_keys, public_ephemeral_string);
	buffer_create_from_string(purported_public_ephemeral_string, "purported_public_ephemeral");
	mcJSON *their_purported_public_ephemeral = mcJSON_GetObjectItem(their_keys, purported_public_ephemeral_string);
	if ((their_public_identity == NULL) || (their_public_identity->type != mcJSON_String) || (their_public_identity->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->type != mcJSON_String) || (their_public_ephemeral->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))
			|| (their_purported_public_ephemeral == NULL) || (their_purported_public_ephemeral->type != mcJSON_String) || (their_purported_public_ephemeral->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))) {
		goto fail;
	}

	//copy to state
	if (buffer_clone_from_hex(state->their_public_identity, their_public_identity->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->their_public_ephemeral, their_public_ephemeral->valuestring) != 0) {
		goto fail;
	}
	if (buffer_clone_from_hex(state->their_purported_public_ephemeral, their_purported_public_ephemeral->valuestring) != 0) {
		goto fail;
	}

	//import message numbers
	//get from json
	buffer_create_from_string(message_numbers_string, "message_numbers");
	mcJSON *message_numbers = mcJSON_GetObjectItem(json, message_numbers_string);
	if ((message_numbers == NULL) || (message_numbers->type != mcJSON_Object)) {
		goto fail;
	}
	buffer_create_from_string(send_message_number_string, "send_message_number");
	mcJSON *send_message_number = mcJSON_GetObjectItem(message_numbers, send_message_number_string);
	buffer_create_from_string(receive_message_number_string, "receive_message_number");
	mcJSON *receive_message_number = mcJSON_GetObjectItem(message_numbers, receive_message_number_string);
	buffer_create_from_string(purported_message_number_string, "purported_message_number");
	mcJSON *purported_message_number = mcJSON_GetObjectItem(message_numbers, purported_message_number_string);
	buffer_create_from_string(previous_message_number_string, "previous_message_number");
	mcJSON *previous_message_number = mcJSON_GetObjectItem(message_numbers, previous_message_number_string);
	buffer_create_from_string(purported_previous_message_number_string, "purported_previous_message_number");
	mcJSON *purported_previous_message_number = mcJSON_GetObjectItem(message_numbers, purported_previous_message_number_string);

	if ((send_message_number == NULL) || (send_message_number->valuedouble > SIZE_MAX) || (send_message_number->valuedouble < 0)
			|| (receive_message_number == NULL) || (receive_message_number->valuedouble > SIZE_MAX) || (receive_message_number->valuedouble < 0)

			|| (purported_message_number == NULL) || (purported_message_number->valuedouble > SIZE_MAX) || (purported_message_number->valuedouble < 0)

			|| (previous_message_number == NULL) || (previous_message_number->valuedouble > SIZE_MAX) || (previous_message_number->valuedouble < 0)

			|| (purported_previous_message_number == NULL) || (purported_previous_message_number->valuedouble > SIZE_MAX) || (purported_previous_message_number->valuedouble < 0)
) {
		goto fail;
	}

	//copy to state
	state->send_message_number = (size_t)send_message_number->valuedouble;
	state->receive_message_number = (size_t)receive_message_number->valuedouble;
	state->previous_message_number = (size_t)previous_message_number->valuedouble;
	state->purported_message_number = (size_t)purported_message_number->valuedouble;
	state->purported_previous_message_number = (size_t)purported_previous_message_number->valuedouble;

	//import other data
	//get from json
	buffer_create_from_string(ratchet_flag_string, "ratchet_flag");
	mcJSON *ratchet_flag = mcJSON_GetObjectItem(json, ratchet_flag_string);
	buffer_create_from_string(am_i_alice_string, "am_i_alice");
	mcJSON *am_i_alice = mcJSON_GetObjectItem(json, am_i_alice_string);
	buffer_create_from_string(received_valid_string, "received_valid");
	mcJSON *received_valid = mcJSON_GetObjectItem(json, received_valid_string);
	buffer_create_from_string(header_decryptable_string, "header_decryptable");
	mcJSON *header_decryptable = mcJSON_GetObjectItem(json, header_decryptable_string);
	if ((ratchet_flag == NULL) || (!mcJSON_IsBoolean(ratchet_flag))
			|| (am_i_alice == NULL) || (!mcJSON_IsBoolean(am_i_alice))
			|| (received_valid == NULL) || (!mcJSON_IsBoolean(received_valid))
			|| (header_decryptable == NULL) || (!mcJSON_IsInteger(header_decryptable))
			|| ((header_decryptable->valueint != CURRENT_DECRYPTABLE) && (header_decryptable->valueint != NEXT_DECRYPTABLE)
				&& (header_decryptable->valueint != UNDECRYPTABLE) && (header_decryptable->valueint != NOT_TRIED))) {
		goto fail;
	}

	//copy to state
	state->ratchet_flag = (ratchet_flag->type == mcJSON_True);
	state->am_i_alice = (am_i_alice->type == mcJSON_True);
	state->received_valid = (received_valid->type == mcJSON_True);
	state->header_decryptable = header_decryptable->valueint;

	//import header and message keystores
	//get from json
	buffer_create_from_string(header_and_message_keystores_string, "header_and_message_keystores");
	mcJSON *keystores = mcJSON_GetObjectItem(json, header_and_message_keystores_string);
	if ((keystores == NULL) || (keystores->type != mcJSON_Object)) {
		goto fail;
	}
	buffer_create_from_string(skipped_header_and_message_keys_string, "skipped_header_and_message_keys");
	mcJSON *skipped_header_and_message_keys = mcJSON_GetObjectItem(keystores, skipped_header_and_message_keys_string);
	buffer_create_from_string(purported_header_and_message_keys_string, "purported_header_and_message_keys");
	mcJSON *purported_header_and_message_keys = mcJSON_GetObjectItem(keystores, purported_header_and_message_keys_string);
	if ((skipped_header_and_message_keys == NULL) || (purported_header_and_message_keys == NULL)) {
		goto fail;
	}

	//copy to state
	if (header_and_message_keystore_json_import(skipped_header_and_message_keys, state->skipped_header_and_message_keys) != 0) {
		goto fail;
	}
	if (header_and_message_keystore_json_import(purported_header_and_message_keys, state->purported_header_and_message_keys) != 0) {
		goto fail;
	}

	return state;
fail:
	ratchet_destroy(state);
	return NULL;
}
