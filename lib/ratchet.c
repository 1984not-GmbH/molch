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
#include <stdint.h>

#include "constants.h"
#include "ratchet.h"
#include "diffie-hellman.h"
#include "key-derivation.h"

/*
 * Helper function that checks if a buffer is <none>
 * (filled with zeroes), and does so without introducing
 * side channels, especially timing side channels.
 */
bool is_none(const buffer_t * const buffer) {
	return (buffer->content_length == 0) || sodium_is_zero(buffer->content, buffer->content_length);
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
	buffer_init_with_pointer(state->root_key, (unsigned char*)state->root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	buffer_init_with_pointer(state->purported_root_key, (unsigned char*)state->purported_root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	//header keys
	buffer_init_with_pointer(state->send_header_key, (unsigned char*)state->send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer(state->receive_header_key, (unsigned char*)state->receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer(state->next_send_header_key, (unsigned char*)state->next_send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer(state->next_receive_header_key, (unsigned char*)state->next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer(state->purported_receive_header_key, (unsigned char*)state->purported_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer(state->purported_next_receive_header_key, (unsigned char*)state->purported_next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	//chain keys
	buffer_init_with_pointer(state->send_chain_key, (unsigned char*)state->send_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer(state->receive_chain_key, (unsigned char*)state->receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer(state->purported_receive_chain_key, (unsigned char*)state->purported_receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	//identity keys
	buffer_init_with_pointer(state->our_public_identity, (unsigned char*)state->our_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(state->their_public_identity, (unsigned char*)state->their_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//ephemeral keys (ratchet keys)
	buffer_init_with_pointer(state->our_private_ephemeral, (unsigned char*)state->our_private_ephemeral_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_init_with_pointer(state->our_public_ephemeral, (unsigned char*)state->our_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(state->their_public_ephemeral, (unsigned char*)state->their_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(state->their_purported_public_ephemeral, (unsigned char*)state->their_purported_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//initialise message keystore for skipped messages
	header_and_message_keystore_init(state->skipped_header_and_message_keys);
	header_and_message_keystore_init(state->staged_header_and_message_keys);

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
	if ((our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
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
 * Get keys and metadata to send the next message.
 */
int ratchet_send(
		ratchet_state *ratchet,
		buffer_t * const send_header_key, //HEADER_KEY_SIZE, HKs
		uint32_t * const send_message_number, //Ns
		uint32_t * const previous_send_message_number, //PNs
		buffer_t * const our_public_ephemeral, //PUBLIC_KEY_SIZE, DHRs
		buffer_t * const message_key) { //MESSAGE_KEY_SIZE, MK
	int status;

	//create buffers
	buffer_t *root_key_backup = buffer_create_on_heap(ROOT_KEY_SIZE, 0);
	buffer_t *chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);

	//check input
	if ((ratchet == NULL)
			|| (send_header_key == NULL) || (send_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (send_message_number == NULL)
			|| (previous_send_message_number == NULL)
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)
			|| (message_key == NULL) || (message_key->buffer_length < MESSAGE_KEY_SIZE)) {
		status = -6;
		goto cleanup;
	}

	if (ratchet->ratchet_flag) {
		//DHRs = generateECDH()
		status = crypto_box_keypair(
				ratchet->our_public_ephemeral->content,
				ratchet->our_private_ephemeral->content);
		ratchet->our_public_ephemeral->content_length = PUBLIC_KEY_SIZE;
		ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
		if (status != 0) {
			goto cleanup;
		}

		//HKs = NHKs
		status = buffer_clone(ratchet->send_header_key, ratchet->next_send_header_key);
		if (status != 0) {
			goto cleanup;
		}

		//clone the root key for it to not be overwritten in the next step
		status = buffer_clone(root_key_backup, ratchet->root_key);
		if (status != 0) {
			goto cleanup;
		}

		//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
		status = derive_root_next_header_and_chain_keys(
				ratchet->root_key,
				ratchet->next_send_header_key,
				ratchet->send_chain_key,
				ratchet->our_private_ephemeral,
				ratchet->our_public_ephemeral,
				ratchet->their_public_ephemeral,
				root_key_backup,
				ratchet->am_i_alice);
		if (status != 0) {
			goto cleanup;
		}

		//PNs = Ns
		ratchet->previous_message_number = ratchet->send_message_number;

		//Ns = 0
		ratchet->send_message_number = 0;

		//ratchet_flag = False
		ratchet->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, "0")
	status = derive_message_key(message_key, ratchet->send_chain_key);
	if (status != 0)  {
		goto cleanup;
	}

	//copy the other data to the output
	//(corresponds to
	//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
	//  in the axolotl specification)
	//HKs:
	status = buffer_clone(send_header_key, ratchet->send_header_key);
	if (status != 0) {
		goto cleanup;
	}
	//Ns
	*send_message_number = ratchet->send_message_number;
	//PNs
	*previous_send_message_number = ratchet->previous_message_number;
	//DHRs
	status = buffer_clone(our_public_ephemeral, ratchet->our_public_ephemeral);
	if (status != 0) {
		goto cleanup;
	}

	//Ns = Ns + 1
	ratchet->send_message_number++;

	//clone the chain key for it to not be overwritten in the next step
	status = buffer_clone(chain_key_backup, ratchet->send_chain_key);
	if (status != 0) {
		goto cleanup;
	}

	//CKs = HMAC-HASH(CKs, "1")
	status = derive_chain_key(
			ratchet->send_chain_key,
			chain_key_backup);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		if (send_header_key != NULL) {
			buffer_clear(send_header_key);
			send_header_key->content_length = 0;
		}
		if (our_public_ephemeral != NULL) {
			buffer_clear(our_public_ephemeral);
			our_public_ephemeral->content_length = 0;
		}
		if (message_key != NULL) {
			buffer_clear(message_key);
			message_key->content_length = 0;
		}
	}

	buffer_destroy_from_heap(root_key_backup);
	buffer_destroy_from_heap(chain_key_backup);

	return status;
}

/*
 * Get a copy of the current and the next receive header key.
 */
int ratchet_get_receive_header_keys(
		buffer_t * const current_receive_header_key,
		buffer_t * const next_receive_header_key,
		ratchet_state *state) {
	int status;

	//check input
	if ((current_receive_header_key == NULL) || (current_receive_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (next_receive_header_key == NULL) || (next_receive_header_key->buffer_length < HEADER_KEY_SIZE)) {
		status = -6;
		goto cleanup;
	}

	//clone the header keys
	status = buffer_clone(current_receive_header_key, state->receive_header_key);
	if (status != 0) {
		return status;
	}
	status = buffer_clone(next_receive_header_key, state->next_receive_header_key);
	if (status != 0) {
		return status;
	}

cleanup:
	if (status != 0) {
		if (current_receive_header_key != NULL) {
			buffer_clear(current_receive_header_key);
			current_receive_header_key->content_length = 0;
		}
		if (next_receive_header_key != NULL) {
			buffer_clear(next_receive_header_key);
			next_receive_header_key->content_length = 0;
		}
	}
	return 0;
}

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
int ratchet_set_header_decryptability(
		ratchet_state *ratchet,
		ratchet_header_decryptability header_decryptable) {
	if (ratchet->header_decryptable != NOT_TRIED) {
		//if the last message hasn't been properly handled yet, abort
		return -10;
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		return -10;
	}

	ratchet->header_decryptable = header_decryptable;

	return 0;
}

/*
 * This corresponds to "stage_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Calculates all the message keys up to the purported message number and
 * saves the skipped ones in the ratchet's staging area.
 */
int stage_skipped_header_and_message_keys(
		header_and_message_keystore * const staging_area,
		buffer_t * const output_chain_key, //output, CHAIN_KEY_SIZE
		buffer_t * const output_message_key, //output, MESSAGE_KEY_SIZE
		const buffer_t * const current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const buffer_t * const chain_key) {
	int status;

	//create buffers
	buffer_t *current_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	buffer_t *next_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	buffer_t *current_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);

	//check input
	if ((staging_area == NULL)
			|| ((output_chain_key != NULL) && (output_chain_key->buffer_length < CHAIN_KEY_SIZE))
			|| ((output_message_key != NULL) && (output_message_key->buffer_length < MESSAGE_KEY_SIZE))
			|| (current_header_key == NULL) || (current_header_key->content_length != HEADER_KEY_SIZE)
			|| (chain_key == NULL) || (chain_key->content_length != CHAIN_KEY_SIZE)) {
		status = -6;
		goto cleanup;
	}

	//when chain key is <none>, do nothing
	if (is_none(chain_key)) {
		status = 0;
		goto cleanup;
	}

	//set current_chain_key to chain key to initialize it for the calculation that's
	//following
	status = buffer_clone(current_chain_key, chain_key);
	if (status != 0) {
		goto cleanup;
	}

	for (uint32_t pos = current_message_number; pos < future_message_number; pos++) {
		//derive current message key
		status = derive_message_key(current_message_key, current_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//add the message key, along with current_header_key to the staging area
		status = header_and_message_keystore_add(
				staging_area,
				current_message_key,
				current_header_key);
		if (status != 0) {
			goto cleanup;
		}

		//derive next chain key
		status = derive_chain_key(next_chain_key, current_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//shift chain keys
		status = buffer_clone(current_chain_key, next_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	}

	//derive the message key that will be returned
	if (output_message_key != NULL) {
		status = derive_message_key(output_message_key, current_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	}

	//derive the chain key that will be returned
	//TODO: not sure if this additional derivation is needed!
	if (output_chain_key != NULL) {
		status = derive_chain_key(output_chain_key, current_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	if (status != 0) {
		if (output_chain_key != NULL) {
			buffer_clear(output_chain_key);
			output_chain_key->content_length = 0;
		}
		if (output_message_key != NULL) {
			buffer_clear(output_message_key);
			output_message_key->content_length = 0;
		}

		header_and_message_keystore_clear(staging_area);
	}

	buffer_destroy_from_heap(current_chain_key);
	buffer_destroy_from_heap(next_chain_key);
	buffer_destroy_from_heap(current_message_key);

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
	while (state->staged_header_and_message_keys->length != 0) {
		status = header_and_message_keystore_add(
				state->skipped_header_and_message_keys,
				state->staged_header_and_message_keys->head->message_key,
				state->staged_header_and_message_keys->head->header_key);
		if (status != 0) {
			return status;
		}
		header_and_message_keystore_remove(
				state->staged_header_and_message_keys,
				state->staged_header_and_message_keys->head);
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
		ratchet_state * const ratchet,
		buffer_t * const message_key,
		const buffer_t * const their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) {
	int status;

	//create buffers
	buffer_t *throwaway_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	buffer_t *throwaway_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);
	buffer_t *purported_chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);

	//check input
	if ((ratchet == NULL)
			|| (message_key == NULL) || (message_key->buffer_length < MESSAGE_KEY_SIZE)
			|| (their_purported_public_ephemeral == NULL) || (their_purported_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		status = -6;
		goto cleanup;
	}

	if (!ratchet->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		status = -10;
		goto cleanup;
	}

	//header decryption hasn't been tried yet
	if (ratchet->header_decryptable == NOT_TRIED) {
		status = -10;
		goto cleanup;
	}

	if (!is_none(ratchet->receive_header_key) && (ratchet->header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//Np = read(): get the purported message number from the input
		ratchet->purported_message_number = purported_message_number;

		//CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
		status = stage_skipped_header_and_message_keys(
				ratchet->staged_header_and_message_keys,
				ratchet->purported_receive_chain_key,
				message_key,
				ratchet->receive_header_key,
				ratchet->receive_message_number,
				purported_message_number,
				ratchet->receive_chain_key);
		if (status != 0) {
			goto cleanup;
		}
	} else { //new message chain
		//if ratchet_flag or not Dec(NHKr, header)
		if (ratchet->ratchet_flag || (ratchet->header_decryptable != NEXT_DECRYPTABLE)) {
			status = -10;
			goto cleanup;
		}

		//Np = read(): get the purported message number from the input
		ratchet->purported_message_number = purported_message_number;
		//PNp = read(): get the purported previous message number from the input
		ratchet->purported_previous_message_number = purported_previous_message_number;
		//DHRp = read(): get the purported ephemeral from the input
		status = buffer_clone(ratchet->their_purported_public_ephemeral, their_purported_public_ephemeral);
		if (status != 0) {
			goto cleanup;
		}

		//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
		status = stage_skipped_header_and_message_keys(
				ratchet->staged_header_and_message_keys,
				NULL, //output_chain_key
				NULL, //output_message_key
				ratchet->receive_header_key,
				ratchet->receive_message_number,
				purported_previous_message_number,
				ratchet->receive_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//HKp = NHKr
		status = buffer_clone(ratchet->purported_receive_header_key, ratchet->next_receive_header_key);
		if (status != 0) {
			goto cleanup;
		}

		//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
		status = derive_root_next_header_and_chain_keys(
				ratchet->purported_root_key,
				ratchet->purported_next_receive_header_key,
				ratchet->purported_receive_chain_key,
				ratchet->our_private_ephemeral,
				ratchet->our_public_ephemeral,
				their_purported_public_ephemeral,
				ratchet->root_key,
				ratchet->am_i_alice);
		if (status != 0) {
			goto cleanup;
		}

		//backup the purported chain key because it will get overwritten in the next step
		status = buffer_clone(purported_chain_key_backup, ratchet->purported_receive_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//backup the purported receive chain key to be able to use it in the next step
		status = buffer_clone(purported_chain_key_backup, ratchet->purported_receive_chain_key);
		if (status != 0) {
			goto cleanup;
		}

		//CKp, MK = staged_header_and_message_keys(HKp, 0, Np, CKp)
		status = stage_skipped_header_and_message_keys(
				ratchet->staged_header_and_message_keys,
				ratchet->purported_receive_chain_key,
				message_key,
				ratchet->purported_receive_header_key,
				0,
				purported_message_number,
				purported_chain_key_backup);
		if (status != 0) {
			goto cleanup;
		}
	}

	ratchet->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)

cleanup:
	if (status != 0) {
		if (message_key != NULL) {
			buffer_clear(message_key);
			message_key->content_length = 0;
		}
	}

	buffer_destroy_from_heap(throwaway_chain_key);
	buffer_destroy_from_heap(throwaway_message_key);
	buffer_destroy_from_heap(purported_chain_key_backup);

	return 0;
}

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
int ratchet_set_last_message_authenticity(
		ratchet_state *ratchet,
		bool valid) {
	//prepare for being able to receive new messages
	ratchet->received_valid = true;

	//backup header decryptability
	ratchet_header_decryptability header_decryptable = ratchet->header_decryptable;
	ratchet->header_decryptable = NOT_TRIED;

	int status;

	if (!valid) { //message couldn't be decrypted
		header_and_message_keystore_clear(ratchet->staged_header_and_message_keys);
		status = 0;
		goto cleanup;
	}

	if (is_none(ratchet->receive_header_key) || (header_decryptable != CURRENT_DECRYPTABLE)) { //new message chain
		if (ratchet->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE)) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			header_and_message_keystore_clear(ratchet->staged_header_and_message_keys);
			status = 0;
			goto cleanup;
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		status = buffer_clone(ratchet->root_key, ratchet->purported_root_key);
		if (status != 0) {
			goto cleanup;
		}
		//HKr = HKp
		status = buffer_clone(ratchet->receive_header_key, ratchet->purported_receive_header_key);
		if (status != 0) {
			goto cleanup;
		}
		//NHKr = NHKp
		status = buffer_clone(ratchet->next_receive_header_key, ratchet->purported_next_receive_header_key);
		if (status != 0) {
			goto cleanup;
		}
		//DHRr = DHRp
		status = buffer_clone(ratchet->their_public_ephemeral, ratchet->their_purported_public_ephemeral);
		if (status != 0) {
			goto cleanup;
		}
		//erase(DHRs)
		buffer_clear(ratchet->our_private_ephemeral);
		ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
		//ratchet_flag = True
		ratchet->ratchet_flag = true;
	}

	//commit_skipped_header_and_message_keys
	status = commit_skipped_header_and_message_keys(ratchet);
	if (status != 0) {
		goto cleanup;
	}
	//Nr = Np + 1
	ratchet->receive_message_number = ratchet->purported_message_number + 1;
	//CKr = CKp
	status = buffer_clone(ratchet->receive_chain_key, ratchet->purported_receive_chain_key);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	return status;
}

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state) {
	//empty message keystores
	header_and_message_keystore_clear(state->skipped_header_and_message_keys);
	header_and_message_keystore_clear(state->staged_header_and_message_keys);

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
	mcJSON *staged_header_and_message_keys = header_and_message_keystore_json_export((header_and_message_keystore * const ) &(state->staged_header_and_message_keys), pool);
	mcJSON *keystores = mcJSON_CreateObject(pool);
	if ((skipped_header_and_message_keys == NULL) || (staged_header_and_message_keys == NULL) || (keystores == NULL)) {
		return NULL;
	}
	buffer_create_from_string(skipped_header_and_message_keys_string, "skipped_header_and_message_keys");
	mcJSON_AddItemToObject(keystores, skipped_header_and_message_keys_string, skipped_header_and_message_keys, pool);
	buffer_create_from_string(staged_header_and_message_keys_string, "staged_header_and_message_keys");
	mcJSON_AddItemToObject(keystores, staged_header_and_message_keys_string, staged_header_and_message_keys, pool);
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
	if ((root_key == NULL) || (root_key->type != mcJSON_String) || (root_key->valuestring->content_length != (2 * ROOT_KEY_SIZE + 1))
			|| (purported_root_key == NULL) || (purported_root_key->type != mcJSON_String) || (purported_root_key->valuestring->content_length != (2 * ROOT_KEY_SIZE + 1))) {
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
	if ((send_header_key == NULL) || (send_header_key->type != mcJSON_String) || (send_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
			|| (receive_header_key == NULL) || (receive_header_key->type != mcJSON_String) || (receive_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
			|| (next_send_header_key == NULL) || (next_send_header_key->type != mcJSON_String) || (next_send_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
			|| (next_receive_header_key == NULL) || (next_receive_header_key->type != mcJSON_String) || (next_receive_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
			|| (purported_receive_header_key == NULL) || (purported_receive_header_key->type != mcJSON_String) || (purported_receive_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
			|| (purported_next_receive_header_key == NULL) || (purported_next_receive_header_key->type != mcJSON_String) || (purported_next_receive_header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))) {
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
	if ((send_chain_key == NULL) || (send_chain_key->type != mcJSON_String) || (send_chain_key->valuestring->content_length != (2 * CHAIN_KEY_SIZE + 1))
			|| (receive_chain_key == NULL) || (receive_chain_key->type != mcJSON_String) || (receive_chain_key->valuestring->content_length != (2 * CHAIN_KEY_SIZE + 1))
			|| (purported_receive_chain_key == NULL) || (purported_receive_chain_key->type != mcJSON_String) || (purported_receive_chain_key->valuestring->content_length != (2 * CHAIN_KEY_SIZE + 1))) {
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
	if ((our_public_identity == NULL) || (our_public_identity->type != mcJSON_String) || (our_public_identity->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->type != mcJSON_String) || (our_public_ephemeral->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (our_private_ephemeral == NULL) || (our_private_ephemeral->type != mcJSON_String) || (our_private_ephemeral->valuestring->content_length != (2 * PRIVATE_KEY_SIZE + 1))) {
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
	if ((their_public_identity == NULL) || (their_public_identity->type != mcJSON_String) || (their_public_identity->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->type != mcJSON_String) || (their_public_ephemeral->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (their_purported_public_ephemeral == NULL) || (their_purported_public_ephemeral->type != mcJSON_String) || (their_purported_public_ephemeral->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))) {
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
	buffer_create_from_string(staged_header_and_message_keys_string, "staged_header_and_message_keys");
	mcJSON *staged_header_and_message_keys = mcJSON_GetObjectItem(keystores, staged_header_and_message_keys_string);
	if ((skipped_header_and_message_keys == NULL) || (staged_header_and_message_keys == NULL)) {
		goto fail;
	}

	//copy to state
	if (header_and_message_keystore_json_import(skipped_header_and_message_keys, state->skipped_header_and_message_keys) != 0) {
		goto fail;
	}
	if (header_and_message_keystore_json_import(staged_header_and_message_keys, state->staged_header_and_message_keys) != 0) {
		goto fail;
	}

	return state;
fail:
	ratchet_destroy(state);
	return NULL;
}
