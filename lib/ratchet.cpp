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
#include <cassert>
#include <cstdint>
#include <exception>

#include "constants.h"
#include "ratchet.h"
#include "key-derivation.h"
#include "molch-exception.h"

void Ratchet::initState() noexcept {
	//initialize the buffers with the storage arrays
	this->root_key.init(this->root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	this->purported_root_key.init(this->purported_root_key_storage, ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	//header keys
	this->send_header_key.init(this->send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	this->receive_header_key.init(this->receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	this->next_send_header_key.init(this->next_send_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	this->next_receive_header_key.init(this->next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	this->purported_receive_header_key.init(this->purported_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	this->purported_next_receive_header_key.init(this->purported_next_receive_header_key_storage, HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	//chain keys
	this->send_chain_key.init(this->send_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	this->receive_chain_key.init(this->receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	this->purported_receive_chain_key.init(this->purported_receive_chain_key_storage, CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	//identity keys
	this->our_public_identity.init(this->our_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	this->their_public_identity.init(this->their_public_identity_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	//ephemeral keys (ratchet keys)
	this->our_private_ephemeral.init(this->our_private_ephemeral_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	this->our_public_ephemeral.init(this->our_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	this->their_public_ephemeral.init(this->their_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	this->their_purported_public_ephemeral.init(this->their_purported_public_ephemeral_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	header_and_message_keystore_init(&this->skipped_header_and_message_keys);
	header_and_message_keystore_init(&this->staged_header_and_message_keys);
}

/*
 * Create a new Ratchet and initialise the pointers.
 */
return_status Ratchet::createState(Ratchet*& ratchet) noexcept {
	return_status status = return_status_init();

	ratchet = (Ratchet*)sodium_malloc(sizeof(Ratchet));
	THROW_on_failed_alloc(ratchet);

	//initialize the buffers with the storage arrays
	ratchet->initState();

	//initialise message keystore for skipped messages
	header_and_message_keystore_init(&ratchet->skipped_header_and_message_keys);
	header_and_message_keystore_init(&ratchet->staged_header_and_message_keys);

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
return_status Ratchet::create(
		Ratchet*& ratchet,
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral) noexcept {
	return_status status = return_status_init();

	//check buffer sizes
	if ((our_private_identity.content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity.content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity.content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral.content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral.content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral.content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_create.");
	}

	ratchet = nullptr;

	status = createState(ratchet);
	THROW_on_error(CREATION_ERROR, "Failed to create ratchet.");

	//find out if we are alice by comparing both public keys
	//the one with the bigger public key is alice
	{
		int comparison = sodium_compare(our_public_identity.content, their_public_identity.content, our_public_identity.content_length);
		if (comparison > 0) {
			ratchet->am_i_alice = true;
		} else if (comparison < 0) {
			ratchet->am_i_alice = false;
		} else {
			THROW(SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
		}
	}

	//derive initial chain, root and header keys
	try {
		derive_initial_root_chain_and_header_keys(
			ratchet->root_key,
			ratchet->send_chain_key,
			ratchet->receive_chain_key,
			ratchet->send_header_key,
			ratchet->receive_header_key,
			ratchet->next_send_header_key,
			ratchet->next_receive_header_key,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			ratchet->am_i_alice);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}
	//copy keys into state
	//our public identity
	if (ratchet->our_public_identity.cloneFrom(&our_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their_public_identity
	if (ratchet->their_public_identity.cloneFrom(&their_public_identity) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	//our_private_ephemeral
	if (ratchet->our_private_ephemeral.cloneFrom(&our_private_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our_public_ephemeral
	if (ratchet->our_public_ephemeral.cloneFrom(&our_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their_public_ephemeral
	if (ratchet->their_public_ephemeral.cloneFrom(&their_public_ephemeral) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral.");
	}

	//set other state
	ratchet->ratchet_flag = ratchet->am_i_alice;
	ratchet->received_valid = true; //allowing the receival of new messages
	ratchet->header_decryptable = NOT_TRIED;
	ratchet->send_message_number = 0;
	ratchet->receive_message_number = 0;
	ratchet->previous_message_number = 0;

cleanup:
	on_error {
		sodium_free_and_null_if_valid(ratchet);
	}

	return status;
}

/*
 * Get keys and metadata to send the next message.
 */
return_status Ratchet::send(
		Buffer& send_header_key_, //HEADER_KEY_SIZE, HKs
		uint32_t& send_message_number_, //Ns
		uint32_t& previous_send_message_number_, //PNs
		Buffer& our_public_ephemeral_, //PUBLIC_KEY_SIZE, DHRs
		Buffer& message_key) noexcept { //MESSAGE_KEY_SIZE, MK
	return_status status = return_status_init();

	//create buffers
	Buffer *root_key_backup = nullptr;
	Buffer *chain_key_backup = nullptr;
	root_key_backup = Buffer::create(ROOT_KEY_SIZE, 0);
	THROW_on_failed_alloc(root_key_backup);
	chain_key_backup = Buffer::create(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(chain_key_backup);

	//check input
	if ((send_header_key_.getBufferLength() < HEADER_KEY_SIZE)
			|| (our_public_ephemeral_.getBufferLength() < PUBLIC_KEY_SIZE)
			|| (message_key.getBufferLength() < MESSAGE_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_send.");
	}

	if (this->ratchet_flag) {
		//DHRs = generateECDH()
		{
			int status_int = crypto_box_keypair(
					this->our_public_ephemeral.content,
					this->our_private_ephemeral.content);
			this->our_public_ephemeral.content_length = PUBLIC_KEY_SIZE;
			this->our_private_ephemeral.content_length = PRIVATE_KEY_SIZE;
			if (status_int != 0) {
				THROW(KEYGENERATION_FAILED, "Failed to generate new ephemeral keypair.");
			}
		}

		//HKs = NHKs
		{
			int status_int = this->send_header_key.cloneFrom(&this->next_send_header_key);
			if (status_int != 0) {
				THROW(BUFFER_ERROR, "Failed to copy send header key to next send header key.");
			}
		}

		//clone the root key for it to not be overwritten in the next step
		{
			int status_int = root_key_backup->cloneFrom(&this->root_key);
			if (status_int != 0) {
				THROW(BUFFER_ERROR, "Failed to backup root key.");
			}
		}

		//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
		try {
			derive_root_next_header_and_chain_keys(
				this->root_key,
				this->next_send_header_key,
				this->send_chain_key,
				this->our_private_ephemeral,
				this->our_public_ephemeral,
				this->their_public_ephemeral,
				*root_key_backup,
				this->am_i_alice);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//PNs = Ns
		this->previous_message_number = this->send_message_number;

		//Ns = 0
		this->send_message_number = 0;

		//ratchet_flag = False
		this->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, "0")
	try {
		derive_message_key(message_key, this->send_chain_key);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//copy the other data to the output
	//(corresponds to
	//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
	//  in the axolotl specification)
	//HKs:
	{
		int status_int = send_header_key_.cloneFrom(&this->send_header_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy send header key.");
		}
	}
	//Ns
	send_message_number_ = this->send_message_number;
	//PNs
	previous_send_message_number_ = this->previous_message_number;
	//DHRs
	{
		int status_int = our_public_ephemeral_.cloneFrom(&this->our_public_ephemeral);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public ephemeral.");
		}
	}

	//Ns = Ns + 1
	this->send_message_number++;

	//clone the chain key for it to not be overwritten in the next step
	{
		int status_int = chain_key_backup->cloneFrom(&this->send_chain_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to backup send chain key.");
		}
	}

	//CKs = HMAC-HASH(CKs, "1")
	try {
		derive_chain_key(
			this->send_chain_key,
			*chain_key_backup);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

cleanup:
	on_error {
		send_header_key_.clear();
		send_header_key_.content_length = 0;
		our_public_ephemeral_.clear();
		our_public_ephemeral_.content_length = 0;
		message_key.clear();
		message_key.content_length = 0;
	}

	buffer_destroy_from_heap_and_null_if_valid(root_key_backup);
	buffer_destroy_from_heap_and_null_if_valid(chain_key_backup);

	return status;
}

/*
 * Get a copy of the current and the next receive header key.
 */
return_status Ratchet::getReceiveHeaderKeys(
		Buffer& current_receive_header_key,
		Buffer& next_receive_header_key) noexcept {
	return_status status = return_status_init();

	//check input
	if ((current_receive_header_key.getBufferLength() < HEADER_KEY_SIZE)
			|| (next_receive_header_key.getBufferLength() < HEADER_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_get_receive_header_keys.");
	}

	//clone the header keys
	if (current_receive_header_key.cloneFrom(&this->receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy current receive header key.");
	}
	if (next_receive_header_key.cloneFrom(&this->next_receive_header_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}

cleanup:
	on_error {
		current_receive_header_key.clear();
		current_receive_header_key.content_length = 0;
		next_receive_header_key.clear();
		next_receive_header_key.content_length = 0;
	}

	return status;
}

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
return_status Ratchet::setHeaderDecryptability(ratchet_header_decryptability header_decryptable) noexcept {
	return_status status = return_status_init();

	if (this->header_decryptable != NOT_TRIED) {
		//if the last message hasn't been properly handled yet, abort
		THROW(GENERIC_ERROR, "Message hasn't been handled yet.");
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		THROW(INVALID_INPUT, "Can't set to \"NOT_TRIED\"");
	}

	this->header_decryptable = header_decryptable;

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
return_status Ratchet::stageSkippedHeaderAndMessageKeys(
		header_and_message_keystore& staging_area,
		Buffer * output_chain_key, //output, optional CHAIN_KEY_SIZE
		Buffer * output_message_key, //output, optional MESSAGE_KEY_SIZE
		const Buffer& current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const Buffer& chain_key) noexcept {
	return_status status = return_status_init();

	//create buffers
	Buffer *current_chain_key = nullptr;
	Buffer *next_chain_key = nullptr;
	Buffer *current_message_key = nullptr;
	current_chain_key = Buffer::create(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(current_chain_key);
	next_chain_key = Buffer::create(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(next_chain_key);
	current_message_key = Buffer::create(MESSAGE_KEY_SIZE, 0);
	THROW_on_failed_alloc(current_message_key);

	//check input
	if (((output_chain_key != nullptr) && (output_chain_key->getBufferLength() < CHAIN_KEY_SIZE))
			|| ((output_message_key != nullptr) && (output_message_key->getBufferLength() < MESSAGE_KEY_SIZE))
			|| (current_header_key.content_length != HEADER_KEY_SIZE)
			|| (chain_key.content_length != CHAIN_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to stage_skipped_header_and_message_keys.");
	}

	//when chain key is <none>, do nothing
	if (chain_key.isNone()) {
		goto cleanup;
	}

	//set current_chain_key to chain key to initialize it for the calculation that's
	//following
	if (current_chain_key->cloneFrom(&chain_key) != 0) {
		goto cleanup;
	}

	for (uint32_t pos = current_message_number; pos < future_message_number; pos++) {
		//derive current message key
		try {
			derive_message_key(*current_message_key, *current_chain_key);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//add the message key, along with current_header_key to the staging area
		status = header_and_message_keystore_add(
				&staging_area,
				current_message_key,
				&current_header_key);
		THROW_on_error(ADDITION_ERROR, "Failed to add keys to header and message keystore.");

		//derive next chain key
		try {
			derive_chain_key(*next_chain_key, *current_chain_key);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//shift chain keys
		if (current_chain_key->cloneFrom(next_chain_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

	//derive the message key that will be returned
	if (output_message_key != nullptr) {
		try {
			derive_message_key(*output_message_key, *current_chain_key);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

	//derive the chain key that will be returned
	if (output_chain_key != nullptr) {
		try {
			derive_chain_key(*output_chain_key, *current_chain_key);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}
	}

cleanup:
	on_error {
		if (output_chain_key != NULL) {
			output_chain_key->clear();
			output_chain_key->content_length = 0;
		}
		if (output_message_key != NULL) {
			output_message_key->clear();
			output_message_key->content_length = 0;
		}
		header_and_message_keystore_clear(&staging_area);
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
return_status Ratchet::commitSkippedHeaderAndMessageKeys() noexcept {
	return_status status = return_status_init();

	//as long as the list of purported message keys isn't empty,
	//add them to the list of skipped message keys
	while (this->staged_header_and_message_keys.length != 0) {
		status = header_and_message_keystore_add(
				&this->skipped_header_and_message_keys,
				this->staged_header_and_message_keys.head->message_key,
				this->staged_header_and_message_keys.head->header_key);
		THROW_on_error(ADDITION_ERROR, "Failed to add keys to skipped header and message keys.");
		header_and_message_keystore_remove(
				&this->staged_header_and_message_keys,
				this->staged_header_and_message_keys.head);
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
return_status Ratchet::receive(
		Buffer& message_key,
		const Buffer& their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) noexcept {
	return_status status = return_status_init();

	//create buffers
	Buffer *purported_chain_key_backup = nullptr;
	purported_chain_key_backup = Buffer::create(CHAIN_KEY_SIZE, 0);
	THROW_on_failed_alloc(purported_chain_key_backup);

	//check input
	if ((message_key.getBufferLength() < MESSAGE_KEY_SIZE)
			|| (their_purported_public_ephemeral.content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to ratchet_receive.");
	}

	if (!this->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		THROW(INVALID_STATE, "Previously received message hasn't been verified yet.");
	}

	//header decryption hasn't been tried yet
	if (this->header_decryptable == NOT_TRIED) {
		THROW(INVALID_STATE, "Header decryption hasn't been tried yet.");
	}

	if (!this->receive_header_key.isNone() && (this->header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//Np = read(): get the purported message number from the input
		this->purported_message_number = purported_message_number;

		//CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
		status = Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				&this->purported_receive_chain_key,
				&message_key,
				this->receive_header_key,
				this->receive_message_number,
				purported_message_number,
				this->receive_chain_key);
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	} else { //new message chain
		//if ratchet_flag or not Dec(NHKr, header)
		if (this->ratchet_flag || (this->header_decryptable != NEXT_DECRYPTABLE)) {
			THROW(DECRYPT_ERROR, "Undecryptable.");
		}

		//Np = read(): get the purported message number from the input
		this->purported_message_number = purported_message_number;
		//PNp = read(): get the purported previous message number from the input
		this->purported_previous_message_number = purported_previous_message_number;
		//DHRp = read(): get the purported ephemeral from the input
		if (this->their_purported_public_ephemeral.cloneFrom(&their_purported_public_ephemeral) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral.");
		}

		//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
		status = Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				nullptr, //output_chain_key
				nullptr, //output_message_key
				this->receive_header_key,
				this->receive_message_number,
				purported_previous_message_number,
				this->receive_chain_key);
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");

		//HKp = NHKr
		if (this->purported_receive_header_key.cloneFrom(&this->next_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy next receive header key to purported receive header key.");
		}

		//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
		try {
			derive_root_next_header_and_chain_keys(
					this->purported_root_key,
					this->purported_next_receive_header_key,
					this->purported_receive_chain_key,
					this->our_private_ephemeral,
					this->our_public_ephemeral,
					their_purported_public_ephemeral,
					this->root_key,
					this->am_i_alice);
		} catch (const MolchException& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(EXCEPTION, exception.what());
		}

		//backup the purported chain key because it will get overwritten in the next step
		if (purported_chain_key_backup->cloneFrom(&this->purported_receive_chain_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to backup purported receive chain key.");
		}

		//CKp, MK = staged_header_and_message_keys(HKp, 0, Np, CKp)
		status = Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				&this->purported_receive_chain_key,
				&message_key,
				this->purported_receive_header_key,
				0,
				purported_message_number,
				*purported_chain_key_backup);
		THROW_on_error(GENERIC_ERROR, "Failed to stage skipped header and message keys.");
	}

	this->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)

cleanup:
	on_error {
		message_key.clear();
		message_key.content_length = 0;
	}

	buffer_destroy_from_heap_and_null_if_valid(purported_chain_key_backup);

	return status;
}

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
return_status Ratchet::setLastMessageAuthenticity(bool valid) noexcept {
	return_status status = return_status_init();

	//prepare for being able to receive new messages
	this->received_valid = true;

	//backup header decryptability
	ratchet_header_decryptability header_decryptable = this->header_decryptable;
	this->header_decryptable = NOT_TRIED;

	if (!valid) { //message couldn't be decrypted
		header_and_message_keystore_clear(&this->staged_header_and_message_keys);
		goto cleanup;
	}

	if (this->receive_header_key.isNone() || (header_decryptable != CURRENT_DECRYPTABLE)) { //new message chain
		if (this->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE)) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			header_and_message_keystore_clear(&this->staged_header_and_message_keys);
			goto cleanup;
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		if (this->root_key.cloneFrom(&this->purported_root_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy purported root key to root key.");
		}
		//HKr = HKp
		if (this->receive_header_key.cloneFrom(&this->purported_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy purported receive header key to receive header key.");
		}
		//NHKr = NHKp
		if (this->next_receive_header_key.cloneFrom(&this->purported_next_receive_header_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy purported next receive header key to next receive header key.");
		}
		//DHRr = DHRp
		if (this->their_public_ephemeral.cloneFrom(&this->their_purported_public_ephemeral) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral to their public ephemeral.");
		}
		//erase(DHRs)
		this->our_private_ephemeral.clear();
		this->our_private_ephemeral.content_length = PRIVATE_KEY_SIZE;
		//ratchet_flag = True
		this->ratchet_flag = true;
	}

	//commit_skipped_header_and_message_keys
	status = this->commitSkippedHeaderAndMessageKeys();
	THROW_on_error(GENERIC_ERROR, "Failed to commit skipped header and message keys.");
	//Nr = Np + 1
	this->receive_message_number = this->purported_message_number + 1;
	//CKr = CKp
	if (this->receive_chain_key.cloneFrom(&this->purported_receive_chain_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key to receive chain key.");
	}

cleanup:
	return status;
}

/*
 * End the ratchet chain and free the memory.
 */
void Ratchet::destroy() noexcept {
	//empty message keystores
	header_and_message_keystore_clear(&this->skipped_header_and_message_keys);
	header_and_message_keystore_clear(&this->staged_header_and_message_keys);

	sodium_free(this); //this also overwrites all the keys with zeroes
}

return_status Ratchet::exportRatchet(Conversation*& conversation) noexcept {
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

	conversation = (Conversation*)zeroed_malloc(sizeof(Conversation));
	THROW_on_failed_alloc(conversation);
	conversation__init(conversation);

	//root keys
	//root key
	root_key = (unsigned char*)zeroed_malloc(ROOT_KEY_SIZE);
	THROW_on_failed_alloc(root_key);
	if (this->root_key.cloneToRaw(root_key, ROOT_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy root key.");
	}
	conversation->root_key.data = root_key;
	conversation->root_key.len = this->root_key.content_length;
	conversation->has_root_key = true;
	//purported root key
	purported_root_key = (unsigned char*)zeroed_malloc(ROOT_KEY_SIZE);
	THROW_on_failed_alloc(purported_root_key);
	if (this->purported_root_key.cloneToRaw(purported_root_key, ROOT_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported root key.");
	}
	conversation->purported_root_key.data = purported_root_key;
	conversation->purported_root_key.len = this->purported_root_key.content_length;
	conversation->has_purported_root_key = true;

	//header keys
	//send header key
	send_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(send_header_key);
	if (this->send_header_key.cloneToRaw(send_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send header key.");
	}
	conversation->send_header_key.data = send_header_key;
	conversation->send_header_key.len = this->send_header_key.content_length;
	conversation->has_send_header_key = true;
	//receive header key
	receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(receive_header_key);
	if (this->receive_header_key.cloneToRaw(receive_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	conversation->receive_header_key.data = receive_header_key;
	conversation->receive_header_key.len = this->receive_header_key.content_length;
	conversation->has_receive_header_key = true;
	//next send header key
	next_send_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(next_send_header_key);
	if (this->next_send_header_key.cloneToRaw(next_send_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	conversation->next_send_header_key.data = next_send_header_key;
	conversation->next_send_header_key.len = this->next_send_header_key.content_length;
	conversation->has_next_send_header_key = true;
	//next receive header key
	next_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(next_receive_header_key);
	if (this->next_receive_header_key.cloneToRaw(next_receive_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	conversation->next_receive_header_key.data = next_receive_header_key;
	conversation->next_receive_header_key.len = this->next_receive_header_key.content_length;
	conversation->has_next_receive_header_key = true;
	//purported receive header key
	purported_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(purported_receive_header_key);
	if (this->purported_receive_header_key.cloneToRaw(purported_receive_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive header key.");
	}
	conversation->purported_receive_header_key.data = purported_receive_header_key;
	conversation->purported_receive_header_key.len = this->purported_receive_header_key.content_length;
	conversation->has_purported_receive_header_key = true;
	//purported next receive header key
	purported_next_receive_header_key = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(purported_next_receive_header_key);
	if (this->purported_next_receive_header_key.cloneToRaw(purported_next_receive_header_key, HEADER_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}
	conversation->purported_next_receive_header_key.data = purported_next_receive_header_key;
	conversation->purported_next_receive_header_key.len = this->purported_next_receive_header_key.content_length;
	conversation->has_purported_next_receive_header_key = true;

	//chain keys
	//send chain key
	send_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(send_chain_key);
	if (this->send_chain_key.cloneToRaw(send_chain_key, CHAIN_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	conversation->send_chain_key.data = send_chain_key;
	conversation->send_chain_key.len = this->send_chain_key.content_length;
	conversation->has_send_chain_key = true;
	//receive chain key
	receive_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(receive_chain_key);
	if (this->receive_chain_key.cloneToRaw(receive_chain_key, CHAIN_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	conversation->receive_chain_key.data = receive_chain_key;
	conversation->receive_chain_key.len = this->receive_chain_key.content_length;
	conversation->has_receive_chain_key = true;
	//purported receive chain key
	purported_receive_chain_key = (unsigned char*)zeroed_malloc(CHAIN_KEY_SIZE);
	THROW_on_failed_alloc(purported_receive_chain_key);
	if (this->purported_receive_chain_key.cloneToRaw(purported_receive_chain_key, CHAIN_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key.");
	}
	conversation->purported_receive_chain_key.data = purported_receive_chain_key;
	conversation->purported_receive_chain_key.len = this->purported_receive_chain_key.content_length;
	conversation->has_purported_receive_chain_key = true;

	//identity key
	//our public identity key
	our_public_identity_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_public_identity_key);
	if (this->our_public_identity.cloneToRaw(our_public_identity_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	conversation->our_public_identity_key.data = our_public_identity_key;
	conversation->our_public_identity_key.len = this->our_public_identity.content_length;
	conversation->has_our_public_identity_key = true;
	//their public identity key
	their_public_identity_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_public_identity_key);
	if (this->their_public_identity.cloneToRaw(their_public_identity_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	conversation->their_public_identity_key.data = their_public_identity_key;
	conversation->their_public_identity_key.len = this->their_public_identity.content_length;
	conversation->has_their_public_identity_key = true;

	//ephemeral keys
	//our private ephemeral key
	our_private_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_private_ephemeral_key);
	if (this->our_private_ephemeral.cloneToRaw(our_private_ephemeral_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	conversation->our_private_ephemeral_key.data = our_private_ephemeral_key;
	conversation->our_private_ephemeral_key.len = this->our_private_ephemeral.content_length;
	conversation->has_our_private_ephemeral_key = true;
	//our public ephemeral key
	our_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(our_public_ephemeral_key);
	if (this->our_public_ephemeral.cloneToRaw(our_public_ephemeral_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	conversation->our_public_ephemeral_key.data = our_public_ephemeral_key;
	conversation->our_public_ephemeral_key.len = this->our_public_ephemeral.content_length;
	conversation->has_our_public_ephemeral_key = true;
	//their public ephemeral key
	their_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_public_ephemeral_key);
	if (this->their_public_ephemeral.cloneToRaw(their_public_ephemeral_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	conversation->their_public_ephemeral_key.data = their_public_ephemeral_key;
	conversation->their_public_ephemeral_key.len = this->their_public_ephemeral.content_length;
	conversation->has_their_public_ephemeral_key = true;
	//their purported public ephemeral key
	their_purported_public_ephemeral_key = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(their_purported_public_ephemeral_key);
	if (this->their_purported_public_ephemeral.cloneToRaw(their_purported_public_ephemeral_key, PUBLIC_KEY_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
	}
	conversation->their_purported_public_ephemeral.data = their_purported_public_ephemeral_key;
	conversation->their_purported_public_ephemeral.len = this->their_purported_public_ephemeral.content_length;
	conversation->has_their_purported_public_ephemeral = true;

	//message numbers
	//send message number
	conversation->has_send_message_number = true;
	conversation->send_message_number = this->send_message_number;
	//receive message number
	conversation->has_receive_message_number = true;
	conversation->receive_message_number = this->receive_message_number;
	//purported message number
	conversation->has_purported_message_number = true;
	conversation->purported_message_number = this->purported_message_number;
	//previous message number
	conversation->has_previous_message_number = true;
	conversation->previous_message_number = this->previous_message_number;
	//purported previous message number
	conversation->has_purported_previous_message_number = true;
	conversation->purported_previous_message_number = this->purported_previous_message_number;

	//flags
	//ratchet flag
	conversation->has_ratchet_flag = true;
	conversation->ratchet_flag = this->ratchet_flag;
	//am I Alice
	conversation->has_am_i_alice = true;
	conversation->am_i_alice = this->am_i_alice;
	//received valid
	conversation->has_received_valid = true;
	conversation->received_valid = this->received_valid;

	//header decryptability
	switch (this->header_decryptable) {
		case CURRENT_DECRYPTABLE:
			conversation->has_header_decryptable = true;
			conversation->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE;
			break;
		case NEXT_DECRYPTABLE:
			conversation->has_header_decryptable = true;
			conversation->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE;
			break;
		case UNDECRYPTABLE:
			conversation->has_header_decryptable = true;
			conversation->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE;
			break;
		case NOT_TRIED:
			conversation->has_header_decryptable = true;
			conversation->header_decryptable = CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED;
			break;
		default:
			conversation->has_header_decryptable = false;
			THROW(INVALID_VALUE, "Invalid value of ratchet->header_decryptable.");
	}

	//keystores
	//skipped header and message keystore
	status = header_and_message_keystore_export(
		&this->skipped_header_and_message_keys,
		&conversation->skipped_header_and_message_keys,
		&conversation->n_skipped_header_and_message_keys);
	THROW_on_error(EXPORT_ERROR, "Failed to export skipped header and message keystore.");
	//staged header and message keystore
	status = header_and_message_keystore_export(
		&this->staged_header_and_message_keys,
		&conversation->staged_header_and_message_keys,
		&conversation->n_staged_header_and_message_keys);
	THROW_on_error(EXPORT_ERROR, "Failed to export staged header and message keystore.");

cleanup:
	on_error {
		zeroed_free_and_null_if_valid(conversation);
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

return_status Ratchet::import(
		Ratchet*& ratchet,
		const Conversation& conversation) noexcept {
	return_status status = return_status_init();

	ratchet = (Ratchet*)sodium_malloc(sizeof(Ratchet));
	THROW_on_failed_alloc(ratchet);

	ratchet->initState();

	//import all the stuff
	//root keys
	//root key
	if (!conversation.has_root_key || (conversation.root_key.len != ROOT_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No root key in Protobuf-C struct.");
	}
	if (ratchet->root_key.cloneFromRaw(conversation.root_key.data, conversation.root_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy root key.");
	}
	//purported root key
	if (!conversation.has_purported_root_key || (conversation.purported_root_key.len != ROOT_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported root key in Protobuf-C struct.");
	}
	if (ratchet->purported_root_key.cloneFromRaw(conversation.purported_root_key.data, conversation.purported_root_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported root key.");
	}

	//header key
	//send header key
	if (!conversation.has_send_header_key || (conversation.send_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No send header key in Protobuf-C struct.");
	}
	if (ratchet->send_header_key.cloneFromRaw(conversation.send_header_key.data, conversation.send_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send header key.");
	}
	//receive header key
	if (!conversation.has_receive_header_key || (conversation.receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive header key in Protobuf-C struct.");
	}
	if (ratchet->receive_header_key.cloneFromRaw(conversation.receive_header_key.data, conversation.receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	//next send header key
	if (!conversation.has_next_send_header_key || (conversation.next_send_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No next send header key in Protobuf-C struct.");
	}
	if (ratchet->next_send_header_key.cloneFromRaw(conversation.next_send_header_key.data, conversation.next_send_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	//next receive header key
	if (!conversation.has_next_receive_header_key || (conversation.next_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No next receive header key in Protobuf-C struct.");
	}
	if (ratchet->next_receive_header_key.cloneFromRaw(conversation.next_receive_header_key.data, conversation.next_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	//purported receive header key
	if (!conversation.has_purported_receive_header_key || (conversation.purported_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported receive header key in Protobuf-C struct.");
	}
	if (ratchet->purported_receive_header_key.cloneFromRaw(conversation.purported_receive_header_key.data, conversation.purported_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive header key.");
	}
	//purported next receive header key
	if (!conversation.has_purported_next_receive_header_key || (conversation.purported_next_receive_header_key.len != HEADER_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported next receive header key in Protobuf-C struct.");
	}
	if (ratchet->purported_next_receive_header_key.cloneFromRaw(conversation.purported_next_receive_header_key.data, conversation.purported_next_receive_header_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported next receive header key.");
	}

	//chain keys
	//send chain key
	if (!conversation.has_send_chain_key || (conversation.send_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No send chain key in Protobuf-C struct.");
	}
	if (ratchet->send_chain_key.cloneFromRaw(conversation.send_chain_key.data, conversation.send_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	//receive chain key
	if (!conversation.has_receive_chain_key || (conversation.receive_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive chain key in Protobuf-C struct.");
	}
	if (ratchet->receive_chain_key.cloneFromRaw(conversation.receive_chain_key.data, conversation.receive_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	//purported receive chain key
	if (!conversation.has_purported_receive_chain_key || (conversation.purported_receive_chain_key.len != CHAIN_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported receive chain key in Protobuf-C struct.");
	}
	if (ratchet->purported_receive_chain_key.cloneFromRaw(conversation.purported_receive_chain_key.data, conversation.purported_receive_chain_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy purported receive chain key.");
	}

	//identity key
	//our public identity key
	if (!conversation.has_our_public_identity_key || (conversation.our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our public identity key in Protobuf-C struct.");
	}
	if (ratchet->our_public_identity.cloneFromRaw(conversation.our_public_identity_key.data, conversation.our_public_identity_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their public identity key
	if (!conversation.has_their_public_identity_key || (conversation.their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their public identity key in Protobuf-C struct.");
	}
	if (ratchet->their_public_identity.cloneFromRaw(conversation.their_public_identity_key.data, conversation.their_public_identity_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public identity key.");
	}

	//ephemeral keys
	//our private ephemeral key
	if (!conversation.has_our_private_ephemeral_key || (conversation.our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our private ephemeral key in Protobuf-C struct.");
	}
	if (ratchet->our_private_ephemeral.cloneFromRaw(conversation.our_private_ephemeral_key.data, conversation.our_private_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our public ephemeral key
	if (!conversation.has_our_public_ephemeral_key || (conversation.our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No our public ephemeral key in Protobuf-C struct.");
	}
	if (ratchet->our_public_ephemeral.cloneFromRaw(conversation.our_public_ephemeral_key.data, conversation.our_public_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their public ephemeral key
	if (!conversation.has_their_public_ephemeral_key || (conversation.their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their public ephemeral key in Protobuf-C struct.");
	}
	if (ratchet->their_public_ephemeral.cloneFromRaw(conversation.their_public_ephemeral_key.data, conversation.their_public_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	//their purported public ephemeral key
	if (!conversation.has_their_purported_public_ephemeral || (conversation.their_purported_public_ephemeral.len != PUBLIC_KEY_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "No their purported public ephemeral key in Protobuf-C struct.");
	}
	if (ratchet->their_purported_public_ephemeral.cloneFromRaw(conversation.their_purported_public_ephemeral.data, conversation.their_purported_public_ephemeral.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
	}

	//message numbers
	//send message number
	if (!conversation.has_send_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct.");
	}
	ratchet->send_message_number = conversation.send_message_number;
	//receive message number
	if (!conversation.has_receive_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct.");
	}
	ratchet->receive_message_number = conversation.receive_message_number;
	//purported message number
	if (!conversation.has_purported_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct.");
	}
	ratchet->purported_message_number = conversation.purported_message_number;
	//previous message number
	if (!conversation.has_previous_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct.");
	}
	ratchet->previous_message_number = conversation.previous_message_number;
	//purported previous message number
	if (!conversation.has_purported_previous_message_number) {
		THROW(PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct.");
	}
	ratchet->purported_previous_message_number = conversation.purported_previous_message_number;


	//flags
	//ratchet flag
	if (!conversation.has_ratchet_flag) {
		THROW(PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct.");
	}
	ratchet->ratchet_flag = conversation.ratchet_flag;
	//am I Alice
	if (!conversation.has_am_i_alice) {
		THROW(PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct.");
	}
	ratchet->am_i_alice = conversation.am_i_alice;
	//received valid
	if (!conversation.has_received_valid) {
		THROW(PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct.");
	}
	ratchet->received_valid = conversation.received_valid;


	//header decryptable
	if (!conversation.has_header_decryptable) {
		THROW(PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct.");
	}
	switch (conversation.header_decryptable) {
		case CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE:
			ratchet->header_decryptable = CURRENT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE:
			ratchet->header_decryptable = NEXT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE:
			ratchet->header_decryptable = UNDECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED:
			ratchet->header_decryptable = NOT_TRIED;
			break;

		default:
			THROW(INVALID_VALUE, "header_decryptable has an invalid value.");
	}

	//header and message keystores
	//skipped heeader and message keys
	status = header_and_message_keystore_import(
		&ratchet->skipped_header_and_message_keys,
		conversation.skipped_header_and_message_keys,
		conversation.n_skipped_header_and_message_keys);
	THROW_on_error(IMPORT_ERROR, "Failed to import skipped header and message keys.");
	//staged heeader and message keys
	status = header_and_message_keystore_import(
		&ratchet->staged_header_and_message_keys,
		conversation.staged_header_and_message_keys,
		conversation.n_staged_header_and_message_keys);
	THROW_on_error(IMPORT_ERROR, "Failed to import staged header and message keys.");

cleanup:
	on_error {
		sodium_free_and_null_if_valid(ratchet);
	}

	return status;
}

