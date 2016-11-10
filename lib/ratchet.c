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

#include <sodium.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "constants.h"
#include "ratchet.h"
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
return_status create_ratchet_state(ratchet_state ** const ratchet) {
	return_status status = return_status_init();

	if (ratchet == NULL) {
		throw(INVALID_INPUT, "Invalid input to create_ratchet_state.");
	}

	*ratchet = sodium_malloc(sizeof(ratchet_state));
	throw_on_failed_alloc(*ratchet);

	//initialize the buffers with the storage arrays
	buffer_init_with_pointer((*ratchet)->root_key, (unsigned char*)(*ratchet)->root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_root_key, (unsigned char*)(*ratchet)->purported_root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	//header keys
	buffer_init_with_pointer((*ratchet)->send_header_key, (unsigned char*)(*ratchet)->send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->receive_header_key, (unsigned char*)(*ratchet)->receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->next_send_header_key, (unsigned char*)(*ratchet)->next_send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->next_receive_header_key, (unsigned char*)(*ratchet)->next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_receive_header_key, (unsigned char*)(*ratchet)->purported_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_next_receive_header_key, (unsigned char*)(*ratchet)->purported_next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	//chain keys
	buffer_init_with_pointer((*ratchet)->send_chain_key, (unsigned char*)(*ratchet)->send_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->receive_chain_key, (unsigned char*)(*ratchet)->receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_receive_chain_key, (unsigned char*)(*ratchet)->purported_receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	//identity keys
	buffer_init_with_pointer((*ratchet)->our_public_identity, (unsigned char*)(*ratchet)->our_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_public_identity, (unsigned char*)(*ratchet)->their_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//ephemeral keys (ratchet keys)
	buffer_init_with_pointer((*ratchet)->our_private_ephemeral, (unsigned char*)(*ratchet)->our_private_ephemeral_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->our_public_ephemeral, (unsigned char*)(*ratchet)->our_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_public_ephemeral, (unsigned char*)(*ratchet)->their_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_purported_public_ephemeral, (unsigned char*)(*ratchet)->their_purported_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	//initialise message keystore for skipped messages
	header_and_message_keystore_init((*ratchet)->skipped_header_and_message_keys);
	header_and_message_keystore_init((*ratchet)->staged_header_and_message_keys);

cleanup:
	return status;
}

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
		const buffer_t * const their_public_ephemeral) {
	return_status status = return_status_init();

	//check buffer sizes
	if ((our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to ratchet_create.");
	}

	*ratchet = NULL;

	status = create_ratchet_state(ratchet);
	throw_on_error(CREATION_ERROR, "Failed to create ratchet.");
	if ((ratchet == NULL) || (*ratchet == NULL)) {
		//FIXME: I'm quite sure this case won't happen, but the static analyzer
		//complains anyway.
		assert(false && "This isn't supposed to happen.");
	}

	//find out if we are alice by comparing both public keys
	//the one with the bigger public key is alice
	int comparison = sodium_compare(our_public_identity->content, their_public_identity->content, our_public_identity->content_length);
	if (comparison > 0) {
		(*ratchet)->am_i_alice = true;
	} else if (comparison < 0) {
		(*ratchet)->am_i_alice = false;
	} else {
		throw(SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
	}

	//derive initial chain, root and header keys
	status = derive_initial_root_chain_and_header_keys(
			(*ratchet)->root_key,
			(*ratchet)->send_chain_key,
			(*ratchet)->receive_chain_key,
			(*ratchet)->send_header_key,
			(*ratchet)->receive_header_key,
			(*ratchet)->next_send_header_key,
			(*ratchet)->next_receive_header_key,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			(*ratchet)->am_i_alice);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive initial root chain and header keys.");
	//copy keys into state
	//our public identity
	if (buffer_clone((*ratchet)->our_public_identity, our_public_identity) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their_public_identity
	if (buffer_clone((*ratchet)->their_public_identity, their_public_identity) != 0) {
		throw(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	//our_private_ephemeral
	if (buffer_clone((*ratchet)->our_private_ephemeral, our_private_ephemeral) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our_public_ephemeral
	if (buffer_clone((*ratchet)->our_public_ephemeral, our_public_ephemeral) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their_public_ephemeral
	if (buffer_clone((*ratchet)->their_public_ephemeral, their_public_ephemeral) != 0) {
		throw(BUFFER_ERROR, "Failed to copy their public ephemeral.");
	}

	//set other state
	(*ratchet)->ratchet_flag = (*ratchet)->am_i_alice;
	(*ratchet)->received_valid = true; //allowing the receival of new messages
	(*ratchet)->header_decryptable = NOT_TRIED;
	(*ratchet)->send_message_number = 0;
	(*ratchet)->receive_message_number = 0;
	(*ratchet)->previous_message_number = 0;

cleanup:
	on_error(
		if (ratchet != NULL) {
				sodium_free_and_null_if_valid(*ratchet);
		}
	)

	return status;
}

/*
 * Get keys and metadata to send the next message.
 */
return_status ratchet_send(
		ratchet_state *ratchet,
		buffer_t * const send_header_key, //HEADER_KEY_SIZE, HKs
		uint32_t * const send_message_number, //Ns
		uint32_t * const previous_send_message_number, //PNs
		buffer_t * const our_public_ephemeral, //PUBLIC_KEY_SIZE, DHRs
		buffer_t * const message_key) { //MESSAGE_KEY_SIZE, MK
	return_status status = return_status_init();

	//create buffers
	buffer_t *root_key_backup = NULL;
	buffer_t *chain_key_backup = NULL;
	root_key_backup = buffer_create_on_heap(ROOT_KEY_SIZE, 0);
	throw_on_failed_alloc(root_key_backup);
	chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	throw_on_failed_alloc(chain_key_backup);

	//check input
	if ((ratchet == NULL)
			|| (send_header_key == NULL) || (send_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (send_message_number == NULL)
			|| (previous_send_message_number == NULL)
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)
			|| (message_key == NULL) || (message_key->buffer_length < MESSAGE_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to ratchet_send.");
	}

	int status_int = 0;

	if (ratchet->ratchet_flag) {
		//DHRs = generateECDH()
		status_int = crypto_box_keypair(
				ratchet->our_public_ephemeral->content,
				ratchet->our_private_ephemeral->content);
		ratchet->our_public_ephemeral->content_length = PUBLIC_KEY_SIZE;
		ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate new ephemeral keypair.");
		}

		//HKs = NHKs
		status_int = buffer_clone(ratchet->send_header_key, ratchet->next_send_header_key);
		if (status_int != 0) {
			throw(BUFFER_ERROR, "Failed to copy send header key to next send header key.");
		}

		//clone the root key for it to not be overwritten in the next step
		status_int = buffer_clone(root_key_backup, ratchet->root_key);
		if (status_int != 0) {
			throw(BUFFER_ERROR, "Failed to backup root key.");
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
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive root next header and chain keys.");

		//PNs = Ns
		ratchet->previous_message_number = ratchet->send_message_number;

		//Ns = 0
		ratchet->send_message_number = 0;

		//ratchet_flag = False
		ratchet->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, "0")
	status = derive_message_key(message_key, ratchet->send_chain_key);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");

	//copy the other data to the output
	//(corresponds to
	//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
	//  in the axolotl specification)
	//HKs:
	status_int = buffer_clone(send_header_key, ratchet->send_header_key);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy send header key.");
	}
	//Ns
	*send_message_number = ratchet->send_message_number;
	//PNs
	*previous_send_message_number = ratchet->previous_message_number;
	//DHRs
	status_int = buffer_clone(our_public_ephemeral, ratchet->our_public_ephemeral);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy public ephemeral.");
	}

	//Ns = Ns + 1
	ratchet->send_message_number++;

	//clone the chain key for it to not be overwritten in the next step
	status_int = buffer_clone(chain_key_backup, ratchet->send_chain_key);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to backup send chain key.");
	}

	//CKs = HMAC-HASH(CKs, "1")
	status = derive_chain_key(
			ratchet->send_chain_key,
			chain_key_backup);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

cleanup:
	on_error(
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
	)

	buffer_destroy_from_heap_and_null_if_valid(root_key_backup);
	buffer_destroy_from_heap_and_null_if_valid(chain_key_backup);

	return status;
}

/*
 * Get a copy of the current and the next receive header key.
 */
return_status ratchet_get_receive_header_keys(
		buffer_t * const current_receive_header_key,
		buffer_t * const next_receive_header_key,
		ratchet_state *state) {
	return_status status = return_status_init();

	//check input
	if ((current_receive_header_key == NULL) || (current_receive_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (next_receive_header_key == NULL) || (next_receive_header_key->buffer_length < HEADER_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to ratchet_get_receive_header_keys.");
	}

	//clone the header keys
	if (buffer_clone(current_receive_header_key, state->receive_header_key) != 0) {
		throw(BUFFER_ERROR, "Failed to copy current receive header key.");
	}
	if (buffer_clone(next_receive_header_key, state->next_receive_header_key) != 0) {
		throw(BUFFER_ERROR, "Failed to copy next receive header key.");
	}

cleanup:
	on_error(
		if (current_receive_header_key != NULL) {
			buffer_clear(current_receive_header_key);
			current_receive_header_key->content_length = 0;
		}
		if (next_receive_header_key != NULL) {
			buffer_clear(next_receive_header_key);
			next_receive_header_key->content_length = 0;
		}
	)

	return status;
}

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
return_status ratchet_set_header_decryptability(
		ratchet_state *ratchet,
		ratchet_header_decryptability header_decryptable) {
	return_status status = return_status_init();

	if (ratchet->header_decryptable != NOT_TRIED) {
		//if the last message hasn't been properly handled yet, abort
		throw(GENERIC_ERROR, "Message hasn't been handled yet.");
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		throw(INVALID_INPUT, "Can't set to \"NOT_TRIED\"");
	}

	ratchet->header_decryptable = header_decryptable;

cleanup:
	return status;
}

/*
 * This corresponds to "stage_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Calculates all the message keys up to the purported message number and
 * saves the skipped ones in the ratchet's staging area.
 */
return_status stage_skipped_header_and_message_keys(
		header_and_message_keystore * const staging_area,
		buffer_t * const output_chain_key, //output, CHAIN_KEY_SIZE
		buffer_t * const output_message_key, //output, MESSAGE_KEY_SIZE
		const buffer_t * const current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const buffer_t * const chain_key) {
	return_status status = return_status_init();

	//create buffers
	buffer_t *current_chain_key = NULL;
	buffer_t *next_chain_key = NULL;
	buffer_t *current_message_key = NULL;
	current_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	throw_on_failed_alloc(current_chain_key);
	next_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	throw_on_failed_alloc(next_chain_key);
	current_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);
	throw_on_failed_alloc(current_message_key);

	//check input
	if ((staging_area == NULL)
			|| ((output_chain_key != NULL) && (output_chain_key->buffer_length < CHAIN_KEY_SIZE))
			|| ((output_message_key != NULL) && (output_message_key->buffer_length < MESSAGE_KEY_SIZE))
			|| (current_header_key == NULL) || (current_header_key->content_length != HEADER_KEY_SIZE)
			|| (chain_key == NULL) || (chain_key->content_length != CHAIN_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to stage_skipped_header_and_message_keys.");
	}

	//when chain key is <none>, do nothing
	if (is_none(chain_key)) {
		goto cleanup;
	}

	//set current_chain_key to chain key to initialize it for the calculation that's
	//following
	if (buffer_clone(current_chain_key, chain_key) != 0) {
		goto cleanup;
	}

	for (uint32_t pos = current_message_number; pos < future_message_number; pos++) {
		//derive current message key
		status = derive_message_key(current_message_key, current_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");

		//add the message key, along with current_header_key to the staging area
		status = header_and_message_keystore_add(
				staging_area,
				current_message_key,
				current_header_key);
		throw_on_error(ADDITION_ERROR, "Failed to add keys to header and message keystore.");

		//derive next chain key
		status = derive_chain_key(next_chain_key, current_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

		//shift chain keys
		if (buffer_clone(current_chain_key, next_chain_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

	//derive the message key that will be returned
	if (output_message_key != NULL) {
		status = derive_message_key(output_message_key, current_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");
	}

	//derive the chain key that will be returned
	//TODO: not sure if this additional derivation is needed!
	if (output_chain_key != NULL) {
		status = derive_chain_key(output_chain_key, current_chain_key);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");
	}

cleanup:
	on_error(
		if (output_chain_key != NULL) {
			buffer_clear(output_chain_key);
			output_chain_key->content_length = 0;
		}
		if (output_message_key != NULL) {
			buffer_clear(output_message_key);
			output_message_key->content_length = 0;
		}

		if (staging_area != NULL) {
			header_and_message_keystore_clear(staging_area);
		}
	)

	buffer_destroy_from_heap_and_null_if_valid(current_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(next_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(current_message_key);

	return status;
}

/*
 * This corresponds to "commit_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Commit all the purported message keys into the message key store thats used
 * to actually decrypt late messages.
 */
return_status commit_skipped_header_and_message_keys(ratchet_state *state) {
	return_status status = return_status_init();

	//as long as the list of purported message keys isn't empty,
	//add them to the list of skipped message keys
	while (state->staged_header_and_message_keys->length != 0) {
		status = header_and_message_keystore_add(
				state->skipped_header_and_message_keys,
				state->staged_header_and_message_keys->head->message_key,
				state->staged_header_and_message_keys->head->header_key);
		throw_on_error(ADDITION_ERROR, "Failed to add keys to skipped header and message keys.");
		header_and_message_keystore_remove(
				state->staged_header_and_message_keys,
				state->staged_header_and_message_keys->head);
	}

cleanup:
	return status;
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
return_status ratchet_receive(
		ratchet_state * const ratchet,
		buffer_t * const message_key,
		const buffer_t * const their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) {
	return_status status = return_status_init();

	//create buffers
	buffer_t *throwaway_chain_key = NULL;
	buffer_t *throwaway_message_key = NULL;
	buffer_t *purported_chain_key_backup = NULL;
	throwaway_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	throw_on_failed_alloc(throwaway_chain_key);
	throwaway_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);
	throw_on_failed_alloc(throwaway_message_key);
	purported_chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	throw_on_failed_alloc(purported_chain_key_backup);

	//check input
	if ((ratchet == NULL)
			|| (message_key == NULL) || (message_key->buffer_length < MESSAGE_KEY_SIZE)
			|| (their_purported_public_ephemeral == NULL) || (their_purported_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to ratchet_receive.");
	}

	if (!ratchet->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		throw(INVALID_STATE, "Previously received message hasn't been verified yet.");
	}

	//header decryption hasn't been tried yet
	if (ratchet->header_decryptable == NOT_TRIED) {
		throw(INVALID_STATE, "Header decryption hasn't been tried yet.");
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
		throw_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	} else { //new message chain
		//if ratchet_flag or not Dec(NHKr, header)
		if (ratchet->ratchet_flag || (ratchet->header_decryptable != NEXT_DECRYPTABLE)) {
			throw(DECRYPT_ERROR, "Undecryptable.");
		}

		//Np = read(): get the purported message number from the input
		ratchet->purported_message_number = purported_message_number;
		//PNp = read(): get the purported previous message number from the input
		ratchet->purported_previous_message_number = purported_previous_message_number;
		//DHRp = read(): get the purported ephemeral from the input
		if (buffer_clone(ratchet->their_purported_public_ephemeral, their_purported_public_ephemeral) != 0) {
			throw(BUFFER_ERROR, "Failed to copy their purported public ephemeral.");
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
		throw_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");

		//HKp = NHKr
		if (buffer_clone(ratchet->purported_receive_header_key, ratchet->next_receive_header_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy next receive header key to purported receive header key.");
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
		throw_on_error(KEYDERIVATION_FAILED, "Faield to derive root next header and chain keys.");

		//backup the purported chain key because it will get overwritten in the next step
		if (buffer_clone(purported_chain_key_backup, ratchet->purported_receive_chain_key) != 0) {
			throw(BUFFER_ERROR, "Failed to backup purported receive chain key.");
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
		throw_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	}

	ratchet->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)

cleanup:
	on_error(
		if (message_key != NULL) {
			buffer_clear(message_key);
			message_key->content_length = 0;
		}
	)

	buffer_destroy_from_heap_and_null_if_valid(throwaway_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(throwaway_message_key);
	buffer_destroy_from_heap_and_null_if_valid(purported_chain_key_backup);

	return status;
}

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
return_status ratchet_set_last_message_authenticity(
		ratchet_state *ratchet,
		bool valid) {
	return_status status = return_status_init();

	//prepare for being able to receive new messages
	ratchet->received_valid = true;

	//backup header decryptability
	ratchet_header_decryptability header_decryptable = ratchet->header_decryptable;
	ratchet->header_decryptable = NOT_TRIED;

	if (!valid) { //message couldn't be decrypted
		header_and_message_keystore_clear(ratchet->staged_header_and_message_keys);
		goto cleanup;
	}

	if (is_none(ratchet->receive_header_key) || (header_decryptable != CURRENT_DECRYPTABLE)) { //new message chain
		if (ratchet->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE)) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			header_and_message_keystore_clear(ratchet->staged_header_and_message_keys);
			goto cleanup;
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		if (buffer_clone(ratchet->root_key, ratchet->purported_root_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy purported root key to root key.");
		}
		//HKr = HKp
		if (buffer_clone(ratchet->receive_header_key, ratchet->purported_receive_header_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy purported receive header key to receive header key.");
		}
		//NHKr = NHKp
		if (buffer_clone(ratchet->next_receive_header_key, ratchet->purported_next_receive_header_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy purported next receive header key to next receive header key.");
		}
		//DHRr = DHRp
		if (buffer_clone(ratchet->their_public_ephemeral, ratchet->their_purported_public_ephemeral) != 0) {
			throw(BUFFER_ERROR, "Failed to copy their purported public ephemeral to their public ephemeral.");
		}
		//erase(DHRs)
		buffer_clear(ratchet->our_private_ephemeral);
		ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
		//ratchet_flag = True
		ratchet->ratchet_flag = true;
	}

	//commit_skipped_header_and_message_keys
	status = commit_skipped_header_and_message_keys(ratchet);
	throw_on_error(GENERIC_ERROR, "Failed to commit skipped header and message keys.");
	//Nr = Np + 1
	ratchet->receive_message_number = ratchet->purported_message_number + 1;
	//CKr = CKp
	if (buffer_clone(ratchet->receive_chain_key, ratchet->purported_receive_chain_key) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported receive chain key to receive chain key.");
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

	sodium_free_and_null_if_valid(state); //this also overwrites all the keys with zeroes
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
	return_status status = return_status_init();

	ratchet_state *state = NULL;

	if ((json == NULL) || (json->type != mcJSON_Object)) {
		throw(INVALID_INPUT, "Invalid input to ratchet_json_import.");
	}

	status = create_ratchet_state(&state);
	throw_on_error(CREATION_ERROR, "Failed to create ratchet state.");

	//import root keys
	//get from json
	buffer_create_from_string(root_keys_string, "root_keys");
	mcJSON *root_keys = mcJSON_GetObjectItem(json, root_keys_string);
	if ((root_keys == NULL) || (root_keys->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get root keys from JSON tree.");
	}

	buffer_create_from_string(root_key_string, "root_key");
	mcJSON *root_key = mcJSON_GetObjectItem(root_keys, root_key_string);
	buffer_create_from_string(purported_root_key_string, "purported_root_key");
	mcJSON *purported_root_key = mcJSON_GetObjectItem(root_keys, purported_root_key_string);
	if ((root_key == NULL) || (root_key->type != mcJSON_String) || (root_key->valuestring->content_length != (2 * ROOT_KEY_SIZE + 1))
			|| (purported_root_key == NULL) || (purported_root_key->type != mcJSON_String) || (purported_root_key->valuestring->content_length != (2 * ROOT_KEY_SIZE + 1))) {
		throw(DATA_FETCH_ERROR, "Failed to get root key and purported root key from JSON tree.");
	}

	//copy to state
	if (buffer_clone_from_hex(state->root_key, root_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy root key from HEX.");
	}
	if (buffer_clone_from_hex(state->purported_root_key, purported_root_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported root key from HEX.");
	}

	//import header keys
	//get from json
	buffer_create_from_string(header_keys_string, "header_keys");
	mcJSON *header_keys = mcJSON_GetObjectItem(json, header_keys_string);
	if ((header_keys == NULL) || (header_keys->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get header keys from JSON tree.");
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
		throw(DATA_FETCH_ERROR, "Failed to get header keys from JSON tree.");
	}

	//copy to state
	if (buffer_clone_from_hex(state->send_header_key, send_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy send header key from HEX.");
	}
	if (buffer_clone_from_hex(state->receive_header_key, receive_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy receive header key from HEX.");
	}
	if (buffer_clone_from_hex(state->next_send_header_key, next_send_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy next send header key from HEX.");
	}
	if (buffer_clone_from_hex(state->next_receive_header_key, next_receive_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy next receive header key from HEX.");
	}
	if (buffer_clone_from_hex(state->purported_receive_header_key, purported_receive_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported receive header key from HEX.");
	}
	if (buffer_clone_from_hex(state->purported_next_receive_header_key, purported_next_receive_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}

	//import chain keys
	//get from json
	buffer_create_from_string(chain_keys_string, "chain_keys");
	mcJSON *chain_keys = mcJSON_GetObjectItem(json, chain_keys_string);
	if ((chain_keys == NULL) || (chain_keys->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get chain keys from JSON tree.");
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
		throw(DATA_FETCH_ERROR, "Failed to get chain keys from JSON tree.");
	}

	//copy to state
	if (buffer_clone_from_hex(state->send_chain_key, send_chain_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy send chain key from HEX.");
	}
	if (buffer_clone_from_hex(state->receive_chain_key, receive_chain_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy receive chain key from HEX.");
	}
	if (buffer_clone_from_hex(state->purported_receive_chain_key, purported_receive_chain_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported receive chain key.");
	}
	if (buffer_clone_from_hex(state->purported_next_receive_header_key, purported_next_receive_header_key->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}

	//import our keys
	//get from json
	buffer_create_from_string(our_keys_string, "our_keys");
	mcJSON *our_keys = mcJSON_GetObjectItem(json, our_keys_string);
	if ((our_keys == NULL) || (our_keys->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get our keys from JSON tree.");
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
		throw(DATA_FETCH_ERROR, "Failed to get our keys from JSON tree.");
	}

	//copy to state
	if (buffer_clone_from_hex(state->our_public_identity, our_public_identity->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our public identity from HEX.");
	}
	if (buffer_clone_from_hex(state->our_public_ephemeral, our_public_ephemeral->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our public ephemeral from HEX.");
	}
	if (buffer_clone_from_hex(state->our_private_ephemeral, our_private_ephemeral->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy our private ephemeral from HEX.");
	}

	//import their keys
	//get from json
	buffer_create_from_string(their_keys_string, "their_keys");
	mcJSON *their_keys = mcJSON_GetObjectItem(json, their_keys_string);
	if ((their_keys == NULL) || (their_keys->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get their keys from JSON tree.");
	}
	mcJSON *their_public_identity = mcJSON_GetObjectItem(their_keys, public_identity_string);
	mcJSON *their_public_ephemeral = mcJSON_GetObjectItem(their_keys, public_ephemeral_string);
	buffer_create_from_string(purported_public_ephemeral_string, "purported_public_ephemeral");
	mcJSON *their_purported_public_ephemeral = mcJSON_GetObjectItem(their_keys, purported_public_ephemeral_string);
	if ((their_public_identity == NULL) || (their_public_identity->type != mcJSON_String) || (their_public_identity->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->type != mcJSON_String) || (their_public_ephemeral->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))
			|| (their_purported_public_ephemeral == NULL) || (their_purported_public_ephemeral->type != mcJSON_String) || (their_purported_public_ephemeral->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))) {
		throw(DATA_FETCH_ERROR, "Failed to get their keys from JSON tree.");
	}

	//copy to state
	if (buffer_clone_from_hex(state->their_public_identity, their_public_identity->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy their public identity from HEX.");
	}
	if (buffer_clone_from_hex(state->their_public_ephemeral, their_public_ephemeral->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy their public ephemeral from HEX.");
	}
	if (buffer_clone_from_hex(state->their_purported_public_ephemeral, their_purported_public_ephemeral->valuestring) != 0) {
		throw(BUFFER_ERROR, "Failed to copy their purported public ephemeral from HEX.");
	}

	//import message numbers
	//get from json
	buffer_create_from_string(message_numbers_string, "message_numbers");
	mcJSON *message_numbers = mcJSON_GetObjectItem(json, message_numbers_string);
	if ((message_numbers == NULL) || (message_numbers->type != mcJSON_Object)) {
		throw(DATA_FETCH_ERROR, "Failed to get message numbers from JSON tree.");
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
		throw(DATA_FETCH_ERROR, "Failed to get message numbers from JSON tree.");
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
		throw(DATA_FETCH_ERROR, "Failed to get other data from JSON tree.")
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
		throw(DATA_FETCH_ERROR, "Failed to get header and message keystores from JSON tree.");
	}
	buffer_create_from_string(skipped_header_and_message_keys_string, "skipped_header_and_message_keys");
	mcJSON *skipped_header_and_message_keys = mcJSON_GetObjectItem(keystores, skipped_header_and_message_keys_string);
	buffer_create_from_string(staged_header_and_message_keys_string, "staged_header_and_message_keys");
	mcJSON *staged_header_and_message_keys = mcJSON_GetObjectItem(keystores, staged_header_and_message_keys_string);
	if ((skipped_header_and_message_keys == NULL) || (staged_header_and_message_keys == NULL)) {
		throw(DATA_FETCH_ERROR, "Failed to get staged header and message keys from JSON tree.");
	}

	//copy to state
	if (header_and_message_keystore_json_import(skipped_header_and_message_keys, state->skipped_header_and_message_keys) != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get skipped hader and message keys from JSON tree.");
	}
	if (header_and_message_keystore_json_import(staged_header_and_message_keys, state->staged_header_and_message_keys) != 0) {
		throw(DATA_FETCH_ERROR, "Failed to get staged header and message keys from JSON tree.");
	}

cleanup:
	on_error(
		if (state != NULL) {
			ratchet_destroy(state);
			state = NULL;
		}
	)

	return_status_destroy_errors(&status);

	return state;
}
