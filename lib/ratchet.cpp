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
#include <cstring>
#include <cassert>
#include <cstdint>

#include "constants.h"
#include "ratchet.h"
#include "key-derivation.h"

/*
 * Helper function that checks if a buffer is <none>
 * (filled with zeroes), and does so without introducing
 * side channels, especially timing side channels.
 */
static bool is_none(const Buffer * const buffer) {
	return (buffer->content_length == 0) || sodium_is_zero(buffer->content, buffer->content_length);
}

static void init_ratchet_state(ratchet_state ** const ratchet) {
	//initialize the buffers with the storage arrays
	buffer_init_with_pointer((*ratchet)->root_key, (*ratchet)->root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_root_key, (*ratchet)->purported_root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	//header keys
	buffer_init_with_pointer((*ratchet)->send_header_key, (*ratchet)->send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->receive_header_key, (*ratchet)->receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->next_send_header_key, (*ratchet)->next_send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->next_receive_header_key, (*ratchet)->next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_receive_header_key, (*ratchet)->purported_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_next_receive_header_key, (*ratchet)->purported_next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	//chain keys
	buffer_init_with_pointer((*ratchet)->send_chain_key, (*ratchet)->send_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->receive_chain_key, (*ratchet)->receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->purported_receive_chain_key, (*ratchet)->purported_receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	//identity keys
	buffer_init_with_pointer((*ratchet)->our_public_identity, (*ratchet)->our_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_public_identity, (*ratchet)->their_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//ephemeral keys (ratchet keys)
	buffer_init_with_pointer((*ratchet)->our_private_ephemeral, (*ratchet)->our_private_ephemeral_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->our_public_ephemeral, (*ratchet)->our_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_public_ephemeral, (*ratchet)->their_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*ratchet)->their_purported_public_ephemeral, (*ratchet)->their_purported_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	header_and_message_keystore_init((*ratchet)->skipped_header_and_message_keys);
	header_and_message_keystore_init((*ratchet)->staged_header_and_message_keys);
}

/*
 * Create a new ratchet_state and initialise the pointers.
 */
static return_status create_ratchet_state(ratchet_state ** const ratchet) {
	return_status status = return_status_init();

	if (ratchet == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to create_ratchet_state.");
	}

	*ratchet = (ratchet_state*)sodium_malloc(sizeof(ratchet_state));
	THROW_on_failed_alloc(*ratchet);

	//initialize the buffers with the storage arrays
	init_ratchet_state(ratchet);

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
 * The return value is a valid ratchet state or nullptr if an error occured.
 */
return_status ratchet_create(
		ratchet_state ** const ratchet,
		const Buffer * const our_private_identity,
		const Buffer * const our_public_identity,
		const Buffer * const their_public_identity,
		const Buffer * const our_private_ephemeral,
		const Buffer * const our_public_ephemeral,
		const Buffer * const their_public_ephemeral) {
	return_status status = return_status_init();

	//check buffer sizes
	if ((our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_create.");
	}

	*ratchet = nullptr;

	status = create_ratchet_state(ratchet);
	THROW_on_error(CREATION_ERROR, "Failed to create ratchet.");
	if ((ratchet == nullptr) || (*ratchet == nullptr)) {
		//FIXME: I'm quite sure this case won't happen, but the static analyzer
		//complains anyway.
		assert(false && "This isn't supposed to happen.");
	}

	//find out if we are alice by comparing both public keys
	//the one with the bigger public key is alice
	{
		int comparison = sodium_compare(our_public_identity->content, their_public_identity->content, our_public_identity->content_length);
		if (comparison > 0) {
			(*ratchet)->am_i_alice = true;
		} else if (comparison < 0) {
			(*ratchet)->am_i_alice = false;
		} else {
			THROW(SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
		}
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
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive initial root chain and header keys.");
	//copy keys into state
	//our public identity
	if (buffer_clone((*ratchet)->our_public_identity, our_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their_public_identity
	if (buffer_clone((*ratchet)->their_public_identity, their_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	//our_private_ephemeral
	if (buffer_clone((*ratchet)->our_private_ephemeral, our_private_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our_public_ephemeral
	if (buffer_clone((*ratchet)->our_public_ephemeral, our_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their_public_ephemeral
	if (buffer_clone((*ratchet)->their_public_ephemeral, their_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral.");
	}

	//set other state
	(*ratchet)->ratchet_flag = (*ratchet)->am_i_alice;
	(*ratchet)->received_valid = true; //allowing the receival of new messages
	(*ratchet)->header_decryptable = NOT_TRIED;
	(*ratchet)->send_message_number = 0;
	(*ratchet)->receive_message_number = 0;
	(*ratchet)->previous_message_number = 0;

cleanup:
	on_error {
		if (ratchet != nullptr) {
				sodium_free_and_null_if_valid(*ratchet);
		}
	}

	return status;
}

/*
 * Get keys and metadata to send the next message.
 */
return_status ratchet_send(
		ratchet_state *ratchet,
		Buffer * const send_header_key, //HEADER_KEY_SIZE, HKs
		uint32_t * const send_message_number, //Ns
		uint32_t * const previous_send_message_number, //PNs
		Buffer * const our_public_ephemeral, //PUBLIC_KEY_SIZE, DHRs
		Buffer * const message_key) { //MESSAGE_KEY_SIZE, MK
	return_status status = return_status_init();

	//create buffers
	Buffer *root_key_backup = nullptr;
	Buffer *chain_key_backup = nullptr;
	root_key_backup = buffer_create_on_heap(ROOT_KEY_SIZE, 0);
	THROW_on_failed_alloc(root_key_backup);
	chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(chain_key_backup);

	//check input
	if ((ratchet == nullptr)
			|| (send_header_key == nullptr) || (send_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (send_message_number == nullptr)
			|| (previous_send_message_number == nullptr)
			|| (our_public_ephemeral == nullptr) || (our_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)
			|| (message_key == nullptr) || (message_key->buffer_length < MESSAGE_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_send.");
	}

	if (ratchet->ratchet_flag) {
		//DHRs = generateECDH()
		{
			int status_int = crypto_box_keypair(
					ratchet->our_public_ephemeral->content,
					ratchet->our_private_ephemeral->content);
			ratchet->our_public_ephemeral->content_length = PUBLIC_KEY_SIZE;
			ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
			if (status_int != 0) {
				THROW(KEYGENERATION_FAILED, "Failed to generate new ephemeral keypair.");
			}
		}

		//HKs = NHKs
		{
			int status_int = buffer_clone(ratchet->send_header_key, ratchet->next_send_header_key);
			if (status_int != 0) {
				THROW(BUFFER_ERROR, "Failed to copy send header key to next send header key.");
			}
		}

		//clone the root key for it to not be overwritten in the next step
		{
			int status_int = buffer_clone(root_key_backup, ratchet->root_key);
			if (status_int != 0) {
				THROW(BUFFER_ERROR, "Failed to backup root key.");
			}
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
		THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive root next header and chain keys.");

		//PNs = Ns
		ratchet->previous_message_number = ratchet->send_message_number;

		//Ns = 0
		ratchet->send_message_number = 0;

		//ratchet_flag = False
		ratchet->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, "0")
	status = derive_message_key(message_key, ratchet->send_chain_key);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");

	//copy the other data to the output
	//(corresponds to
	//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
	//  in the axolotl specification)
	//HKs:
	{
		int status_int = buffer_clone(send_header_key, ratchet->send_header_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy send header key.");
		}
	}
	//Ns
	*send_message_number = ratchet->send_message_number;
	//PNs
	*previous_send_message_number = ratchet->previous_message_number;
	//DHRs
	{
		int status_int = buffer_clone(our_public_ephemeral, ratchet->our_public_ephemeral);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public ephemeral.");
		}
	}

	//Ns = Ns + 1
	ratchet->send_message_number++;

	//clone the chain key for it to not be overwritten in the next step
	{
		int status_int = buffer_clone(chain_key_backup, ratchet->send_chain_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to backup send chain key.");
		}
	}

	//CKs = HMAC-HASH(CKs, "1")
	status = derive_chain_key(
			ratchet->send_chain_key,
			chain_key_backup);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

cleanup:
	on_error {
		if (send_header_key != nullptr) {
			buffer_clear(send_header_key);
			send_header_key->content_length = 0;
		}
		if (our_public_ephemeral != nullptr) {
			buffer_clear(our_public_ephemeral);
			our_public_ephemeral->content_length = 0;
		}
		if (message_key != nullptr) {
			buffer_clear(message_key);
			message_key->content_length = 0;
		}
	}

	buffer_destroy_from_heap_and_null_if_valid(root_key_backup);
	buffer_destroy_from_heap_and_null_if_valid(chain_key_backup);

	return status;
}

/*
 * Get a copy of the current and the next receive header key.
 */
return_status ratchet_get_receive_header_keys(
		Buffer * const current_receive_header_key,
		Buffer * const next_receive_header_key,
		ratchet_state *state) {
	return_status status = return_status_init();

	//check input
	if ((current_receive_header_key == nullptr) || (current_receive_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (next_receive_header_key == nullptr) || (next_receive_header_key->buffer_length < HEADER_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_get_receive_header_keys.");
	}

	//clone the header keys
	if (buffer_clone(current_receive_header_key, state->receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy current receive header key.");
	}
	if (buffer_clone(next_receive_header_key, state->next_receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}

cleanup:
	on_error {
		if (current_receive_header_key != nullptr) {
			buffer_clear(current_receive_header_key);
			current_receive_header_key->content_length = 0;
		}
		if (next_receive_header_key != nullptr) {
			buffer_clear(next_receive_header_key);
			next_receive_header_key->content_length = 0;
		}
	}

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
		THROW(GENERIC_ERROR, "Message hasn't been handled yet.");
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		THROW(INVALID_INPUT, "Can't set to \"NOT_TRIED\"");
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
static return_status stage_skipped_header_and_message_keys(
		header_and_message_keystore * const staging_area,
		Buffer * const output_chain_key, //output, CHAIN_KEY_SIZE
		Buffer * const output_message_key, //output, MESSAGE_KEY_SIZE
		const Buffer * const current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const Buffer * const chain_key) {
	return_status status = return_status_init();

	//create buffers
	Buffer *current_chain_key = nullptr;
	Buffer *next_chain_key = nullptr;
	Buffer *current_message_key = nullptr;
	current_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(current_chain_key);
	next_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(next_chain_key);
	current_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);
	THROW_on_failed_alloc(current_message_key);

	//check input
	if ((staging_area == nullptr)
			|| ((output_chain_key != nullptr) && (output_chain_key->buffer_length < CHAIN_KEY_SIZE))
			|| ((output_message_key != nullptr) && (output_message_key->buffer_length < MESSAGE_KEY_SIZE))
			|| (current_header_key == nullptr) || (current_header_key->content_length != HEADER_KEY_SIZE)
			|| (chain_key == nullptr) || (chain_key->content_length != CHAIN_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to stage_skipped_header_and_message_keys.");
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
		THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");

		//add the message key, along with current_header_key to the staging area
		status = header_and_message_keystore_add(
				staging_area,
				current_message_key,
				current_header_key);
		THROW_on_error(ADDITION_ERROR, "Failed to add keys to header and message keystore.");

		//derive next chain key
		status = derive_chain_key(next_chain_key, current_chain_key);
		THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");

		//shift chain keys
		if (buffer_clone(current_chain_key, next_chain_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

	//derive the message key that will be returned
	if (output_message_key != nullptr) {
		status = derive_message_key(output_message_key, current_chain_key);
		THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive message key.");
	}

	//derive the chain key that will be returned
	//TODO: not sure if this additional derivation is needed!
	if (output_chain_key != nullptr) {
		status = derive_chain_key(output_chain_key, current_chain_key);
		THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key.");
	}

cleanup:
	on_error {
		if (output_chain_key != nullptr) {
			buffer_clear(output_chain_key);
			output_chain_key->content_length = 0;
		}
		if (output_message_key != nullptr) {
			buffer_clear(output_message_key);
			output_message_key->content_length = 0;
		}

		if (staging_area != nullptr) {
			header_and_message_keystore_clear(staging_area);
		}
	}

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
static return_status commit_skipped_header_and_message_keys(ratchet_state *state) {
	return_status status = return_status_init();

	//as long as the list of purported message keys isn't empty,
	//add them to the list of skipped message keys
	while (state->staged_header_and_message_keys->length != 0) {
		status = header_and_message_keystore_add(
				state->skipped_header_and_message_keys,
				state->staged_header_and_message_keys->head->message_key,
				state->staged_header_and_message_keys->head->header_key);
		THROW_on_error(ADDITION_ERROR, "Failed to add keys to skipped header and message keys.");
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
		Buffer * const message_key,
		const Buffer * const their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) {
	return_status status = return_status_init();

	//create buffers
	Buffer *THROWaway_chain_key = nullptr;
	Buffer *THROWaway_message_key = nullptr;
	Buffer *purported_chain_key_backup = nullptr;
	THROWaway_chain_key = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(THROWaway_chain_key);
	THROWaway_message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, 0);
	THROW_on_failed_alloc(THROWaway_message_key);
	purported_chain_key_backup = buffer_create_on_heap(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(purported_chain_key_backup);

	//check input
	if ((ratchet == nullptr)
			|| (message_key == nullptr) || (message_key->buffer_length < MESSAGE_KEY_SIZE)
			|| (their_purported_public_ephemeral == nullptr) || (their_purported_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_receive.");
	}

	if (!ratchet->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		THROW(INVALID_STATE, "Previously received message hasn't been verified yet.");
	}

	//header decryption hasn't been tried yet
	if (ratchet->header_decryptable == NOT_TRIED) {
		THROW(INVALID_STATE, "Header decryption hasn't been tried yet.");
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
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	} else { //new message chain
		//if ratchet_flag or not Dec(NHKr, header)
		if (ratchet->ratchet_flag || (ratchet->header_decryptable != NEXT_DECRYPTABLE)) {
			THROW(DECRYPT_ERROR, "Undecryptable.");
		}

		//Np = read(): get the purported message number from the input
		ratchet->purported_message_number = purported_message_number;
		//PNp = read(): get the purported previous message number from the input
		ratchet->purported_previous_message_number = purported_previous_message_number;
		//DHRp = read(): get the purported ephemeral from the input
		if (buffer_clone(ratchet->their_purported_public_ephemeral, their_purported_public_ephemeral) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral.");
		}

		//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
		status = stage_skipped_header_and_message_keys(
				ratchet->staged_header_and_message_keys,
				nullptr, //output_chain_key
				nullptr, //output_message_key
				ratchet->receive_header_key,
				ratchet->receive_message_number,
				purported_previous_message_number,
				ratchet->receive_chain_key);
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");

		//HKp = NHKr
		if (buffer_clone(ratchet->purported_receive_header_key, ratchet->next_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy next receive header key to purported receive header key.");
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
		THROW_on_error(KEYDERIVATION_FAILED, "Faield to derive root next header and chain keys.");

		//backup the purported chain key because it will get overwritten in the next step
		if (buffer_clone(purported_chain_key_backup, ratchet->purported_receive_chain_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to backup purported receive chain key.");
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
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	}

	ratchet->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)

cleanup:
	on_error {
		if (message_key != nullptr) {
			buffer_clear(message_key);
			message_key->content_length = 0;
		}
	}

	buffer_destroy_from_heap_and_null_if_valid(THROWaway_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(THROWaway_message_key);
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
			THROW(BUFFER_ERROR, "Failed to copy purported root key to root key.");
		}
		//HKr = HKp
		if (buffer_clone(ratchet->receive_header_key, ratchet->purported_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy purported receive header key to receive header key.");
		}
		//NHKr = NHKp
		if (buffer_clone(ratchet->next_receive_header_key, ratchet->purported_next_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy purported next receive header key to next receive header key.");
		}
		//DHRr = DHRp
		if (buffer_clone(ratchet->their_public_ephemeral, ratchet->their_purported_public_ephemeral) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral to their public ephemeral.");
		}
		//erase(DHRs)
		buffer_clear(ratchet->our_private_ephemeral);
		ratchet->our_private_ephemeral->content_length = PRIVATE_KEY_SIZE;
		//ratchet_flag = True
		ratchet->ratchet_flag = true;
	}

	//commit_skipped_header_and_message_keys
	status = commit_skipped_header_and_message_keys(ratchet);
	THROW_on_error(GENERIC_ERROR, "Failed to commit skipped header and message keys.");
	//Nr = Np + 1
	ratchet->receive_message_number = ratchet->purported_message_number + 1;
	//CKr = CKp
	if (buffer_clone(ratchet->receive_chain_key, ratchet->purported_receive_chain_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key to receive chain key.");
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

return_status ratchet_export(
		const ratchet_state * const ratchet,
		Conversation ** const conversation) {
	return_status status = return_status_init();

	//root keys
	unsigned char *root_key = nullptr;
	unsigned char *purported_root_key = nullptr;
	//header keys
	unsigned char *send_header_key = nullptr;
	unsigned char *receive_header_key = nullptr;
	unsigned char *next_send_header_key = nullptr;
	unsigned char *next_receive_header_key = nullptr;
	unsigned char *purported_receive_header_key = nullptr;
	unsigned char *purported_next_receive_header_key = nullptr;
	//chain key
	unsigned char *send_chain_key = nullptr;
	unsigned char *receive_chain_key = nullptr;
	unsigned char *purported_receive_chain_key = nullptr;
	//identity key
	unsigned char *our_public_identity_key = nullptr;
	unsigned char *their_public_identity_key = nullptr;
	//ephemeral keys
	unsigned char *our_private_ephemeral_key = nullptr;
	unsigned char *our_public_ephemeral_key = nullptr;
	unsigned char *their_public_ephemeral_key = nullptr;
	unsigned char *their_purported_public_ephemeral_key = nullptr;

	//check input
	if ((ratchet == nullptr) || (conversation == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_export.");
	}

	*conversation = (Conversation*)zeroed_malloc(sizeof(Conversation));
	THROW_on_failed_alloc(*conversation);
	conversation__init(*conversation);

	//root keys
	//root key
	root_key = (unsigned char*)zeroed_malloc(ROOT_KEY_SIZE);
	THROW_on_failed_alloc(root_key);
	if (buffer_clone_to_raw(root_key, ROOT_KEY_SIZE, ratchet->root_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy root key.");
	}
	(*conversation)->root_key.data = root_key;
	(*conversation)->root_key.len = ratchet->root_key->content_length;
	(*conversation)->has_root_key = true;
	//purported root key
	purported_root_key = (unsigned char*)zeroed_malloc(ROOT_KEY_SIZE);
	THROW_on_failed_alloc(purported_root_key);
	if (buffer_clone_to_raw(purported_root_key, ROOT_KEY_SIZE, ratchet->purported_root_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported root key.");
	}
	(*conversation)->purported_root_key.data = purported_root_key;
	(*conversation)->purported_root_key.len = ratchet->purported_root_key->content_length;
	(*conversation)->has_purported_root_key = true;

	//header keys
	//send header key
	send_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(send_header_key);
	if (buffer_clone_to_raw(send_header_key, HEADER_KEY_SIZE, ratchet->send_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send header key.");
	}
	(*conversation)->send_header_key.data = send_header_key;
	(*conversation)->send_header_key.len = ratchet->send_header_key->content_length;
	(*conversation)->has_send_header_key = true;
	//receive header key
	receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(receive_header_key);
	if (buffer_clone_to_raw(receive_header_key, HEADER_KEY_SIZE, ratchet->receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	(*conversation)->receive_header_key.data = receive_header_key;
	(*conversation)->receive_header_key.len = ratchet->receive_header_key->content_length;
	(*conversation)->has_receive_header_key = true;
	//next send header key
	next_send_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(next_send_header_key);
	if (buffer_clone_to_raw(next_send_header_key, HEADER_KEY_SIZE, ratchet->next_send_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	(*conversation)->next_send_header_key.data = next_send_header_key;
	(*conversation)->next_send_header_key.len = ratchet->next_send_header_key->content_length;
	(*conversation)->has_next_send_header_key = true;
	//next receive header key
	next_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(next_receive_header_key);
	if (buffer_clone_to_raw(next_receive_header_key, HEADER_KEY_SIZE, ratchet->next_receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	(*conversation)->next_receive_header_key.data = next_receive_header_key;
	(*conversation)->next_receive_header_key.len = ratchet->next_receive_header_key->content_length;
	(*conversation)->has_next_receive_header_key = true;
	//purported receive header key
	purported_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(purported_receive_header_key);
	if (buffer_clone_to_raw(purported_receive_header_key, HEADER_KEY_SIZE, ratchet->purported_receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive header key.");
	}
	(*conversation)->purported_receive_header_key.data = purported_receive_header_key;
	(*conversation)->purported_receive_header_key.len = ratchet->purported_receive_header_key->content_length;
	(*conversation)->has_purported_receive_header_key = true;
	//purported next receive header key
	purported_next_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(purported_next_receive_header_key);
	if (buffer_clone_to_raw(purported_next_receive_header_key, HEADER_KEY_SIZE, ratchet->purported_next_receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}
	(*conversation)->purported_next_receive_header_key.data = purported_next_receive_header_key;
	(*conversation)->purported_next_receive_header_key.len = ratchet->purported_next_receive_header_key->content_length;
	(*conversation)->has_purported_next_receive_header_key = true;

	//chain keys
	//send chain key
	send_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(send_chain_key);
	if (buffer_clone_to_raw(send_chain_key, CHAIN_KEY_SIZE, ratchet->send_chain_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	(*conversation)->send_chain_key.data = send_chain_key;
	(*conversation)->send_chain_key.len = ratchet->send_chain_key->content_length;
	(*conversation)->has_send_chain_key = true;
	//receive chain key
	receive_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(receive_chain_key);
	if (buffer_clone_to_raw(receive_chain_key, CHAIN_KEY_SIZE, ratchet->receive_chain_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	(*conversation)->receive_chain_key.data = receive_chain_key;
	(*conversation)->receive_chain_key.len = ratchet->receive_chain_key->content_length;
	(*conversation)->has_receive_chain_key = true;
	//purported receive chain key
	purported_receive_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(purported_receive_chain_key);
	if (buffer_clone_to_raw(purported_receive_chain_key, CHAIN_KEY_SIZE, ratchet->purported_receive_chain_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key.");
	}
	(*conversation)->purported_receive_chain_key.data = purported_receive_chain_key;
	(*conversation)->purported_receive_chain_key.len = ratchet->purported_receive_chain_key->content_length;
	(*conversation)->has_purported_receive_chain_key = true;

	//identity key
	//our public identity key
	our_public_identity_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_public_identity_key);
	if (buffer_clone_to_raw(our_public_identity_key, PUBLIC_KEY_SIZE, ratchet->our_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	(*conversation)->our_public_identity_key.data = our_public_identity_key;
	(*conversation)->our_public_identity_key.len = ratchet->our_public_identity->content_length;
	(*conversation)->has_our_public_identity_key = true;
	//their public identity key
	their_public_identity_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_public_identity_key);
	if (buffer_clone_to_raw(their_public_identity_key, PUBLIC_KEY_SIZE, ratchet->their_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	(*conversation)->their_public_identity_key.data = their_public_identity_key;
	(*conversation)->their_public_identity_key.len = ratchet->their_public_identity->content_length;
	(*conversation)->has_their_public_identity_key = true;

	//ephemeral keys
	//our private ephemeral key
	our_private_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_private_ephemeral_key);
	if (buffer_clone_to_raw(our_private_ephemeral_key, PUBLIC_KEY_SIZE, ratchet->our_private_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	(*conversation)->our_private_ephemeral_key.data = our_private_ephemeral_key;
	(*conversation)->our_private_ephemeral_key.len = ratchet->our_private_ephemeral->content_length;
	(*conversation)->has_our_private_ephemeral_key = true;
	//our public ephemeral key
	our_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_public_ephemeral_key);
	if (buffer_clone_to_raw(our_public_ephemeral_key, PUBLIC_KEY_SIZE, ratchet->our_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	(*conversation)->our_public_ephemeral_key.data = our_public_ephemeral_key;
	(*conversation)->our_public_ephemeral_key.len = ratchet->our_public_ephemeral->content_length;
	(*conversation)->has_our_public_ephemeral_key = true;
	//their public ephemeral key
	their_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_public_ephemeral_key);
	if (buffer_clone_to_raw(their_public_ephemeral_key, PUBLIC_KEY_SIZE, ratchet->their_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	(*conversation)->their_public_ephemeral_key.data = their_public_ephemeral_key;
	(*conversation)->their_public_ephemeral_key.len = ratchet->their_public_ephemeral->content_length;
	(*conversation)->has_their_public_ephemeral_key = true;
	//their purported public ephemeral key
	their_purported_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_purported_public_ephemeral_key);
	if (buffer_clone_to_raw(their_purported_public_ephemeral_key, PUBLIC_KEY_SIZE, ratchet->their_purported_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
	}
	(*conversation)->their_purported_public_ephemeral.data = their_purported_public_ephemeral_key;
	(*conversation)->their_purported_public_ephemeral.len = ratchet->their_purported_public_ephemeral->content_length;
	(*conversation)->has_their_purported_public_ephemeral = true;

	//message numbers
	//send message number
	(*conversation)->has_send_message_number = true;
	(*conversation)->send_message_number = ratchet->send_message_number;
	//receive message number
	(*conversation)->has_receive_message_number = true;
	(*conversation)->receive_message_number = ratchet->receive_message_number;
	//purported message number
	(*conversation)->has_purported_message_number = true;
	(*conversation)->purported_message_number = ratchet->purported_message_number;
	//previous message number
	(*conversation)->has_previous_message_number = true;
	(*conversation)->previous_message_number = ratchet->previous_message_number;
	//purported previous message number
	(*conversation)->has_purported_previous_message_number = true;
	(*conversation)->purported_previous_message_number = ratchet->purported_previous_message_number;

	//flags
	//ratchet flag
	(*conversation)->has_ratchet_flag = true;
	(*conversation)->ratchet_flag = ratchet->ratchet_flag;
	//am I Alice
	(*conversation)->has_am_i_alice = true;
	(*conversation)->am_i_alice = ratchet->am_i_alice;
	//received valid
	(*conversation)->has_received_valid = true;
	(*conversation)->received_valid = ratchet->received_valid;

	//header decryptability
	switch (ratchet->header_decryptable) {
		case CURRENT_DECRYPTABLE:
			(*conversation)->has_header_decryptable = true;
			(*conversation)->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE;
			break;
		case NEXT_DECRYPTABLE:
			(*conversation)->has_header_decryptable = true;
			(*conversation)->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE;
			break;
		case UNDECRYPTABLE:
			(*conversation)->has_header_decryptable = true;
			(*conversation)->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE;
			break;
		case NOT_TRIED:
			(*conversation)->has_header_decryptable = true;
			(*conversation)->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED;
			break;
		default:
			(*conversation)->has_header_decryptable = false;
			THROW(INVALID_VALUE, "Invalid value of ratchet->header_decryptable.");
	}

	//keystores
	//skipped header and message keystore
	status = header_and_message_keystore_export(
		ratchet->skipped_header_and_message_keys,
		&((*conversation)->skipped_header_and_message_keys),
		&((*conversation)->n_skipped_header_and_message_keys));
	THROW_on_error(EXPORT_ERROR, "Failed to export skipped header and message keystore.");
	//staged header and message keystore
	status = header_and_message_keystore_export(
		ratchet->staged_header_and_message_keys,
		&((*conversation)->staged_header_and_message_keys),
		&((*conversation)->n_staged_header_and_message_keys));
	THROW_on_error(EXPORT_ERROR, "Failed to export staged header and message keystore.");

cleanup:
	on_error {
		if (conversation != nullptr) {
			zeroed_free_and_null_if_valid(*conversation);
		}
		//root keys
		zeroed_free_and_null_if_valid(root_key);
		zeroed_free_and_null_if_valid(purported_root_key);
		//header keys
		zeroed_free_and_null_if_valid(send_header_key);
		zeroed_free_and_null_if_valid(receive_header_key);
		zeroed_free_and_null_if_valid(next_send_header_key);
		zeroed_free_and_null_if_valid(next_receive_header_key);
		zeroed_free_and_null_if_valid(purported_receive_header_key);
		zeroed_free_and_null_if_valid(purported_next_receive_header_key);
		//chain keys
		zeroed_free_and_null_if_valid(send_chain_key);
		zeroed_free_and_null_if_valid(receive_chain_key);
		zeroed_free_and_null_if_valid(purported_receive_chain_key);
		//identity key
		zeroed_free_and_null_if_valid(their_public_identity_key);
		//ephemeral key
		zeroed_free_and_null_if_valid(our_private_ephemeral_key);
		zeroed_free_and_null_if_valid(our_public_ephemeral_key);
		zeroed_free_and_null_if_valid(their_public_ephemeral_key);
		zeroed_free_and_null_if_valid(their_purported_public_ephemeral_key);
	}

	return status;
}

return_status ratchet_import(
		ratchet_state ** const ratchet,
		const Conversation * const conversation) {
	return_status status = return_status_init();

	//check input
	if ((ratchet == nullptr) || (conversation == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_import.");
	}

	*ratchet = (ratchet_state*)sodium_malloc(sizeof(ratchet_state));
	THROW_on_failed_alloc(*ratchet);

	init_ratchet_state(ratchet);

	//import all the stuff
	//root keys
	//root key
	if (!conversation->has_root_key || (conversation->root_key.len != ROOT_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No root key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->root_key, conversation->root_key.data, conversation->root_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy root key.");
	}
	//purported root key
	if (!conversation->has_purported_root_key || (conversation->purported_root_key.len != ROOT_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported root key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->purported_root_key, conversation->purported_root_key.data, conversation->purported_root_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported root key.");
	}

	//header key
	//send header key
	if (!conversation->has_send_header_key || (conversation->send_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No send header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->send_header_key, conversation->send_header_key.data, conversation->send_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send header key.");
	}
	//receive header key
	if (!conversation->has_receive_header_key || (conversation->receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->receive_header_key, conversation->receive_header_key.data, conversation->receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	//next send header key
	if (!conversation->has_next_send_header_key || (conversation->next_send_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No next send header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->next_send_header_key, conversation->next_send_header_key.data, conversation->next_send_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	//next receive header key
	if (!conversation->has_next_receive_header_key || (conversation->next_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No next receive header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->next_receive_header_key, conversation->next_receive_header_key.data, conversation->next_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	//purported receive header key
	if (!conversation->has_purported_receive_header_key || (conversation->purported_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported receive header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->purported_receive_header_key, conversation->purported_receive_header_key.data, conversation->purported_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive header key.");
	}
	//purported next receive header key
	if (!conversation->has_purported_next_receive_header_key || (conversation->purported_next_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported next receive header key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->purported_next_receive_header_key, conversation->purported_next_receive_header_key.data, conversation->purported_next_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}

	//chain keys
	//send chain key
	if (!conversation->has_send_chain_key || (conversation->send_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No send chain key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->send_chain_key, conversation->send_chain_key.data, conversation->send_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	//receive chain key
	if (!conversation->has_receive_chain_key || (conversation->receive_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive chain key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->receive_chain_key, conversation->receive_chain_key.data, conversation->receive_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	//purported receive chain key
	if (!conversation->has_purported_receive_chain_key || (conversation->purported_receive_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported receive chain key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->purported_receive_chain_key, conversation->purported_receive_chain_key.data, conversation->purported_receive_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key.");
	}

	//identity key
	//our public identity key
	if (!conversation->has_our_public_identity_key || (conversation->our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our public identity key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->our_public_identity, conversation->our_public_identity_key.data, conversation->our_public_identity_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their public identity key
	if (!conversation->has_their_public_identity_key || (conversation->their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their public identity key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->their_public_identity, conversation->their_public_identity_key.data, conversation->their_public_identity_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}

	//ephemeral keys
	//our private ephemeral key
	if (!conversation->has_our_private_ephemeral_key || (conversation->our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our private ephemeral key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->our_private_ephemeral, conversation->our_private_ephemeral_key.data, conversation->our_private_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our public ephemeral key
	if (!conversation->has_our_public_ephemeral_key || (conversation->our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our public ephemeral key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->our_public_ephemeral, conversation->our_public_ephemeral_key.data, conversation->our_public_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their public ephemeral key
	if (!conversation->has_their_public_ephemeral_key || (conversation->their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their public ephemeral key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->their_public_ephemeral, conversation->their_public_ephemeral_key.data, conversation->their_public_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	//their purported public ephemeral key
	if (!conversation->has_their_purported_public_ephemeral || (conversation->their_purported_public_ephemeral.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their purported public ephemeral key in Protobuf-C struct.");
	}
	if (buffer_clone_from_raw((*ratchet)->their_purported_public_ephemeral, conversation->their_purported_public_ephemeral.data, conversation->their_purported_public_ephemeral.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
	}

	//message numbers
	//send message number
	if (!conversation->has_send_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct.");
	}
	(*ratchet)->send_message_number = conversation->send_message_number;
	//receive message number
	if (!conversation->has_receive_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct.");
	}
	(*ratchet)->receive_message_number = conversation->receive_message_number;
	//purported message number
	if (!conversation->has_purported_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct.");
	}
	(*ratchet)->purported_message_number = conversation->purported_message_number;
	//previous message number
	if (!conversation->has_previous_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct.");
	}
	(*ratchet)->previous_message_number = conversation->previous_message_number;
	//purported previous message number
	if (!conversation->has_purported_previous_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct.");
	}
	(*ratchet)->purported_previous_message_number = conversation->purported_previous_message_number;


	//flags
	//ratchet flag
	if (!conversation->has_ratchet_flag) {
		THROW(PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct.");
	}
	(*ratchet)->ratchet_flag = conversation->ratchet_flag;
	//am I Alice
	if (!conversation->has_am_i_alice) {
		THROW(PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct.");
	}
	(*ratchet)->am_i_alice = conversation->am_i_alice;
	//received valid
	if (!conversation->has_received_valid) {
		THROW(PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct.");
	}
	(*ratchet)->received_valid = conversation->received_valid;


	//header decryptable
	if (!conversation->has_header_decryptable) {
		THROW(PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct.");
	}
	switch (conversation->header_decryptable) {
		case CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE:
			(*ratchet)->header_decryptable = CURRENT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE:
			(*ratchet)->header_decryptable = NEXT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE:
			(*ratchet)->header_decryptable = UNDECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED:
			(*ratchet)->header_decryptable = NOT_TRIED;
			break;

		default:
			THROW(INVALID_VALUE, "header_decryptable has an invalid value.");
	}

	//header and message keystores
	//skipped heeader and message keys
	status = header_and_message_keystore_import(
		(*ratchet)->skipped_header_and_message_keys,
		conversation->skipped_header_and_message_keys,
		conversation->n_skipped_header_and_message_keys);
	THROW_on_error(IMPORT_ERROR, "Failed to import skipped header and message keys.");
	//staged heeader and message keys
	status = header_and_message_keystore_import(
		(*ratchet)->staged_header_and_message_keys,
		conversation->staged_header_and_message_keys,
		conversation->n_staged_header_and_message_keys);
	THROW_on_error(IMPORT_ERROR, "Failed to import staged header and message keys.");

cleanup:
	on_error {
		if (ratchet != nullptr) {
			sodium_free_and_null_if_valid(*ratchet);
		}
	}

	return status;
}

