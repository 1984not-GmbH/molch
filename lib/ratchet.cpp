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
#include <cstdint>
#include <exception>

#include "constants.h"
#include "ratchet.hpp"
#include "key-derivation.hpp"
#include "molch-exception.hpp"

void Ratchet::init() {
	this->storage = std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>>(throwing_sodium_malloc<RatchetStorage>(sizeof(RatchetStorage)));
	new (this->storage.get()) RatchetStorage{};
}

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 */
Ratchet::Ratchet(
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral) {
	//check buffer sizes
	if (!our_private_identity.contains(PRIVATE_KEY_SIZE)
			|| !our_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !their_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !our_private_ephemeral.contains(PRIVATE_KEY_SIZE)
			|| !our_public_ephemeral.contains(PUBLIC_KEY_SIZE)
			|| !their_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to ratchet_create.");
	}

	this->init();

	//find out if we are alice by comparing both public keys
	//the one with the bigger public key is alice
	int comparison = sodium_compare(our_public_identity.content, their_public_identity.content, our_public_identity.content_length);
	if (comparison > 0) {
		this->am_i_alice = true;
	} else if (comparison < 0) {
		this->am_i_alice = false;
	} else {
		throw MolchException(SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
	}

	//derive initial chain, root and header keys
	derive_initial_root_chain_and_header_keys(
		this->storage->root_key,
		this->storage->send_chain_key,
		this->storage->receive_chain_key,
		this->storage->send_header_key,
		this->storage->receive_header_key,
		this->storage->next_send_header_key,
		this->storage->next_receive_header_key,
		our_private_identity,
		our_public_identity,
		their_public_identity,
		our_private_ephemeral,
		our_public_ephemeral,
		their_public_ephemeral,
		this->am_i_alice);

	//copy keys into state
	//our public identity
	if (this->storage->our_public_identity.cloneFrom(&our_public_identity) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their_public_identity
	if (this->storage->their_public_identity.cloneFrom(&their_public_identity) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	//our_private_ephemeral
	if (this->storage->our_private_ephemeral.cloneFrom(&our_private_ephemeral) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our_public_ephemeral
	if (this->storage->our_public_ephemeral.cloneFrom(&our_public_ephemeral) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their_public_ephemeral
	if (this->storage->their_public_ephemeral.cloneFrom(&their_public_ephemeral) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public ephemeral.");
	}

	//set other state
	this->ratchet_flag = this->am_i_alice;
	this->received_valid = true; //allowing the receival of new messages
	this->header_decryptable = NOT_TRIED;
	this->send_message_number = 0;
	this->receive_message_number = 0;
	this->previous_message_number = 0;
}

/*
 * Get keys and metadata to send the next message.
 */
void Ratchet::send(
		Buffer& send_header_key, //HEADER_KEY_SIZE, HKs
		uint32_t& send_message_number, //Ns
		uint32_t& previous_send_message_number, //PNs
		Buffer& our_public_ephemeral, //PUBLIC_KEY_SIZE, DHRs
		Buffer& message_key) { //MESSAGE_KEY_SIZE, MK
	//create buffers
	Buffer root_key_backup(ROOT_KEY_SIZE, 0);
	Buffer chain_key_backup(ROOT_KEY_SIZE, 0);
	exception_on_invalid_buffer(root_key_backup);
	exception_on_invalid_buffer(chain_key_backup);

	//check input
	if (!send_header_key.fits(HEADER_KEY_SIZE)
			|| !our_public_ephemeral.fits(PUBLIC_KEY_SIZE)
			|| !message_key.fits(MESSAGE_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to ratchet_send.");
	}

	if (this->ratchet_flag) {
		//DHRs = generateECDH()
		int status = crypto_box_keypair(
				this->storage->our_public_ephemeral.content,
				this->storage->our_private_ephemeral.content);
		this->storage->our_public_ephemeral.content_length = PUBLIC_KEY_SIZE;
		this->storage->our_private_ephemeral.content_length = PRIVATE_KEY_SIZE;
		if (status != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate new ephemeral keypair.");
		}

		//HKs = NHKs
		status = this->storage->send_header_key.cloneFrom(&this->storage->next_send_header_key);
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy send header key to next send header key.");
		}

		//clone the root key for it to not be overwritten in the next step
		int status_int = root_key_backup.cloneFrom(&this->storage->root_key);
		if (status_int != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to backup root key.");
		}

		//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
		derive_root_next_header_and_chain_keys(
			this->storage->root_key,
			this->storage->next_send_header_key,
			this->storage->send_chain_key,
			this->storage->our_private_ephemeral,
			this->storage->our_public_ephemeral,
			this->storage->their_public_ephemeral,
			root_key_backup,
			this->am_i_alice);

		//PNs = Ns
		this->previous_message_number = this->send_message_number;

		//Ns = 0
		this->send_message_number = 0;

		//ratchet_flag = False
		this->ratchet_flag = false;
	}

	//MK = HMAC-HASH(CKs, "0")
	derive_message_key(message_key, this->storage->send_chain_key);

	//copy the other data to the output
	//(corresponds to
	//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
	//  in the axolotl specification)
	//HKs:
	int status = send_header_key.cloneFrom(&this->storage->send_header_key);
	if (status != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy send header key.");
	}
	//Ns
	send_message_number = this->send_message_number;
	//PNs
	previous_send_message_number = this->previous_message_number;
	//DHRs
	status = our_public_ephemeral.cloneFrom(&this->storage->our_public_ephemeral);
	if (status != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy public ephemeral.");
	}

	//Ns = Ns + 1
	this->send_message_number++;

	//clone the chain key for it to not be overwritten in the next step
	status = chain_key_backup.cloneFrom(&this->storage->send_chain_key);
	if (status != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to backup send chain key.");
	}

	//CKs = HMAC-HASH(CKs, "1")
	derive_chain_key(this->storage->send_chain_key, chain_key_backup);
}

/*
 * Get a copy of the current and the next receive header key.
 */
void Ratchet::getReceiveHeaderKeys(
		Buffer& current_receive_header_key,
		Buffer& next_receive_header_key) const {
	//check input
	if (!current_receive_header_key.fits(HEADER_KEY_SIZE)
			|| !next_receive_header_key.fits(HEADER_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to ratchet_get_receive_header_keys.");
	}

	//clone the header keys
	if (current_receive_header_key.cloneFrom(&this->storage->receive_header_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy current receive header key.");
	}
	if (next_receive_header_key.cloneFrom(&this->storage->next_receive_header_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
}

/*
 * Set if the header is decryptable with the current (state->receive_header_key)
 * or next (next_receive_header_key) header key, or isn't decryptable.
 */
void Ratchet::setHeaderDecryptability(const ratchet_header_decryptability header_decryptable) {
	if (this->header_decryptable != NOT_TRIED) {
		//if the last message hasn't been properly handled yet, abort
		throw MolchException(GENERIC_ERROR, "Message hasn't been handled yet.");
	}

	if (header_decryptable == NOT_TRIED) {
		//can't set to "NOT_TRIED"
		throw MolchException(INVALID_INPUT, "Can't set to \"NOT_TRIED\"");
	}

	this->header_decryptable = header_decryptable;
}

/*
 * This corresponds to "stage_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Calculates all the message keys up to the purported message number and
 * saves the skipped ones in the ratchet's staging area.
 */
void Ratchet::stageSkippedHeaderAndMessageKeys(
		HeaderAndMessageKeyStore& staging_area,
		Buffer * const output_chain_key, //output, optional CHAIN_KEY_SIZE
		Buffer * const output_message_key, //output, optional MESSAGE_KEY_SIZE
		const Buffer& current_header_key,
		const uint32_t current_message_number,
		const uint32_t future_message_number,
		const Buffer& chain_key) {
	//create buffers
	Buffer current_chain_key(CHAIN_KEY_SIZE, 0);
	Buffer next_chain_key(CHAIN_KEY_SIZE, 0);
	Buffer current_message_key(MESSAGE_KEY_SIZE, 0);
	exception_on_invalid_buffer(current_chain_key);
	exception_on_invalid_buffer(next_chain_key);
	exception_on_invalid_buffer(current_message_key);

	//check input
	if (((output_chain_key != nullptr) && !output_chain_key->fits(CHAIN_KEY_SIZE))
			|| ((output_message_key != nullptr) && !output_message_key->fits(MESSAGE_KEY_SIZE))
			|| !current_header_key.contains(HEADER_KEY_SIZE)
			|| !chain_key.contains(CHAIN_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to stage_skipped_header_and_message_keys.");
	}

	//when chain key is <none>, do nothing
	if (chain_key.isNone()) {
		return;
	}

	//set current_chain_key to chain key to initialize it for the calculation that's
	//following
	if (current_chain_key.cloneFrom(&chain_key) != 0) {
		return;
	}

	for (uint32_t pos = current_message_number; pos < future_message_number; pos++) {
		//derive current message key
		derive_message_key(current_message_key, current_chain_key);

		//add the message key, along with current_header_key to the staging area
		staging_area.add(current_header_key, current_message_key);

		//derive next chain key
		derive_chain_key(next_chain_key, current_chain_key);

		//shift chain keys
		if (current_chain_key.cloneFrom(&next_chain_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy chain key.");
		}
	}

	//derive the message key that will be returned
	if (output_message_key != nullptr) {
		derive_message_key(*output_message_key, current_chain_key);
	}

	//derive the chain key that will be returned
	if (output_chain_key != nullptr) {
		derive_chain_key(*output_chain_key, current_chain_key);
	}
}

/*
 * This corresponds to "commit_skipped_header_and_message_keys" from the
 * axolotl protocol description.
 *
 * Commit all the purported message keys into the message key store thats used
 * to actually decrypt late messages.
 */
void Ratchet::commitSkippedHeaderAndMessageKeys() {
	for (auto&& key_bundle : this->staged_header_and_message_keys.keys) {
		this->skipped_header_and_message_keys.keys.push_back(key_bundle);
	}
	this->staged_header_and_message_keys.keys.clear();
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
void Ratchet::receive(
		Buffer& message_key,
		const Buffer& their_purported_public_ephemeral,
		const uint32_t purported_message_number,
		const uint32_t purported_previous_message_number) {
	//create buffers
	Buffer purported_chain_key_backup(CHAIN_KEY_SIZE, 0);
	exception_on_invalid_buffer(purported_chain_key_backup);

	//check input
	if (!message_key.fits(MESSAGE_KEY_SIZE)
			|| !their_purported_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to ratchet_receive.");
	}

	if (!this->received_valid) {
		//abort because the previously received message hasn't been verified yet.
		throw MolchException(INVALID_STATE, "Previously received message hasn't been verified yet.");
	}

	//header decryption hasn't been tried yet
	if (this->header_decryptable == NOT_TRIED) {
		throw MolchException(INVALID_STATE, "Header decryption hasn't been tried yet.");
	}

	if (!this->storage->receive_header_key.isNone() && (this->header_decryptable == CURRENT_DECRYPTABLE)) { //still the same message chain
		//Np = read(): get the purported message number from the input
		this->purported_message_number = purported_message_number;

		//CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
		Ratchet::stageSkippedHeaderAndMessageKeys(
			this->staged_header_and_message_keys,
			&this->storage->purported_receive_chain_key,
			&message_key,
			this->storage->receive_header_key,
			this->receive_message_number,
			purported_message_number,
			this->storage->receive_chain_key);
	} else { //new message chain
		//if ratchet_flag or not Dec(NHKr, header)
		if (this->ratchet_flag || (this->header_decryptable != NEXT_DECRYPTABLE)) {
			throw MolchException(DECRYPT_ERROR, "Undecryptable.");
		}

		//Np = read(): get the purported message number from the input
		this->purported_message_number = purported_message_number;
		//PNp = read(): get the purported previous message number from the input
		this->purported_previous_message_number = purported_previous_message_number;
		//DHRp = read(): get the purported ephemeral from the input
		if (this->storage->their_purported_public_ephemeral.cloneFrom(&their_purported_public_ephemeral) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy their purported public ephemeral.");
		}

		//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
		Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				nullptr, //output_chain_key
				nullptr, //output_message_key
				this->storage->receive_header_key,
				this->receive_message_number,
				purported_previous_message_number,
				this->storage->receive_chain_key);

		//HKp = NHKr
		if (this->storage->purported_receive_header_key.cloneFrom(&this->storage->next_receive_header_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy next receive header key to purported receive header key.");
		}

		//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
		derive_root_next_header_and_chain_keys(
				this->storage->purported_root_key,
				this->storage->purported_next_receive_header_key,
				this->storage->purported_receive_chain_key,
				this->storage->our_private_ephemeral,
				this->storage->our_public_ephemeral,
				their_purported_public_ephemeral,
				this->storage->root_key,
				this->am_i_alice);

		//backup the purported chain key because it will get overwritten in the next step
		if (purported_chain_key_backup.cloneFrom(&this->storage->purported_receive_chain_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to backup purported receive chain key.");
		}

		//CKp, MK = staged_header_and_message_keys(HKp, 0, Np, CKp)
		Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				&this->storage->purported_receive_chain_key,
				&message_key,
				this->storage->purported_receive_header_key,
				0,
				purported_message_number,
				purported_chain_key_backup);
	}

	this->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)
}

/*
 * Call this function after trying to decrypt a message and pass it if
 * the decryption was successful or if it wasn't.
 */
void Ratchet::setLastMessageAuthenticity(bool valid) {
	//prepare for being able to receive new messages
	this->received_valid = true;

	//backup header decryptability
	ratchet_header_decryptability header_decryptable = this->header_decryptable;
	this->header_decryptable = NOT_TRIED;

	if (!valid) { //message couldn't be decrypted
		this->staged_header_and_message_keys.keys.clear();
		return;
	}

	if (this->storage->receive_header_key.isNone() || (header_decryptable != CURRENT_DECRYPTABLE)) { //new message chain
		if (this->ratchet_flag || (header_decryptable != NEXT_DECRYPTABLE)) {
			//if ratchet_flag or not Dec(NHKr, header)
			//clear purported message and header keys
			this->staged_header_and_message_keys.keys.clear();
			return;
		}

		//otherwise, received message was valid
		//accept purported values
		//RK = RKp
		if (this->storage->root_key.cloneFrom(&this->storage->purported_root_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported root key to root key.");
		}
		//HKr = HKp
		if (this->storage->receive_header_key.cloneFrom(&this->storage->purported_receive_header_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported receive header key to receive header key.");
		}
		//NHKr = NHKp
		if (this->storage->next_receive_header_key.cloneFrom(&this->storage->purported_next_receive_header_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported next receive header key to next receive header key.");
		}
		//DHRr = DHRp
		if (this->storage->their_public_ephemeral.cloneFrom(&this->storage->their_purported_public_ephemeral) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy their purported public ephemeral to their public ephemeral.");
		}
		//erase(DHRs)
		this->storage->our_private_ephemeral.clear();
		this->storage->our_private_ephemeral.content_length = PRIVATE_KEY_SIZE;
		//ratchet_flag = True
		this->ratchet_flag = true;
	}

	//commit_skipped_header_and_message_keys
	this->commitSkippedHeaderAndMessageKeys();
	//Nr = Np + 1
	this->receive_message_number = this->purported_message_number + 1;
	//CKr = CKp
	if (this->storage->receive_chain_key.cloneFrom(&this->storage->purported_receive_chain_key) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy purported receive chain key to receive chain key.");
	}
}

std::unique_ptr<Conversation,ConversationDeleter> Ratchet::exportProtobuf() const {
	auto conversation = std::unique_ptr<Conversation,ConversationDeleter>(throwing_zeroed_malloc<Conversation>(sizeof(Conversation)));
	conversation__init(conversation.get());

	//root keys
	//root key
	if (!this->storage->root_key.contains(ROOT_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "root_key is missing or has an incorrect size.");
	}
	conversation->root_key.data = throwing_zeroed_malloc<unsigned char>(ROOT_KEY_SIZE);
	if (this->storage->root_key.cloneToRaw(conversation->root_key.data, ROOT_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy root key.");
	}
	conversation->root_key.len = ROOT_KEY_SIZE;
	conversation->has_root_key = true;
	//purported root key
	if (this->storage->purported_root_key.contains(ROOT_KEY_SIZE)) {
		conversation->purported_root_key.data = throwing_zeroed_malloc<unsigned char>(ROOT_KEY_SIZE);
		if (this->storage->purported_root_key.cloneToRaw(conversation->purported_root_key.data, ROOT_KEY_SIZE) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported root key.");
		}
		conversation->purported_root_key.len = ROOT_KEY_SIZE;
		conversation->has_purported_root_key = true;
	}

	//header keys
	//send header key
	if (!this->am_i_alice && !this->storage->send_header_key.contains(HEADER_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "send_header_key missing or has an incorrect size.");
	}
	conversation->send_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
	if (this->storage->send_header_key.cloneToRaw(conversation->send_header_key.data, HEADER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy send header key.");
	}
	conversation->send_header_key.len = HEADER_KEY_SIZE;
	conversation->has_send_header_key = true;
	//receive header key
	if (this->am_i_alice && !this->storage->receive_header_key.contains(HEADER_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "receive_header_key missing or has an incorrect size.");
	}
	conversation->receive_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
	if (this->storage->receive_header_key.cloneToRaw(conversation->receive_header_key.data, HEADER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	conversation->receive_header_key.len = HEADER_KEY_SIZE;
	conversation->has_receive_header_key = true;
	//next send header key
	if (!this->storage->next_send_header_key.contains(HEADER_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "next_send_header_key missing or has incorrect size.");
	}
	conversation->next_send_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
	if (this->storage->next_send_header_key.cloneToRaw(conversation->next_send_header_key.data, HEADER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	conversation->next_send_header_key.len = HEADER_KEY_SIZE;
	conversation->has_next_send_header_key = true;
	//next receive header key
	if (!this->storage->next_receive_header_key.contains(HEADER_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "next_receive_header_key missinge or has an incorrect size.");
	}
	conversation->next_receive_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
	if (this->storage->next_receive_header_key.cloneToRaw(conversation->next_receive_header_key.data, HEADER_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	conversation->next_receive_header_key.len = HEADER_KEY_SIZE;
	conversation->has_next_receive_header_key = true;
	//purported receive header key
	if (this->storage->purported_receive_header_key.contains(HEADER_KEY_SIZE)) {
		conversation->purported_receive_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
		if (this->storage->purported_receive_header_key.cloneToRaw(conversation->purported_receive_header_key.data, HEADER_KEY_SIZE) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported receive header key.");
		}
		conversation->purported_receive_header_key.len = HEADER_KEY_SIZE;
		conversation->has_purported_receive_header_key = true;
	}
	//purported next receive header key
	if (this->storage->purported_next_receive_header_key.contains(HEADER_KEY_SIZE)) {
		conversation->purported_next_receive_header_key.data = throwing_zeroed_malloc<unsigned char>(HEADER_KEY_SIZE);
		if (this->storage->purported_next_receive_header_key.cloneToRaw(conversation->purported_next_receive_header_key.data, HEADER_KEY_SIZE) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported next receive header key.");
		}
		conversation->purported_next_receive_header_key.len = HEADER_KEY_SIZE;
		conversation->has_purported_next_receive_header_key = true;
	}

	//chain keys
	//send chain key
	if (!this->am_i_alice && !this->storage->send_chain_key.contains(CHAIN_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "send_chain_key missing or has an invalid size.");
	}
	conversation->send_chain_key.data = throwing_zeroed_malloc<unsigned char>(CHAIN_KEY_SIZE);
	if (this->storage->send_chain_key.cloneToRaw(conversation->send_chain_key.data, CHAIN_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	conversation->send_chain_key.len = CHAIN_KEY_SIZE;
	conversation->has_send_chain_key = true;
	//receive chain key
	if (this->am_i_alice && !this->storage->receive_chain_key.contains(CHAIN_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "receive_chain_key missing or has an incorrect size.");
	}
	conversation->receive_chain_key.data = throwing_zeroed_malloc<unsigned char>(CHAIN_KEY_SIZE);
	if (this->storage->receive_chain_key.cloneToRaw(conversation->receive_chain_key.data, CHAIN_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	conversation->receive_chain_key.len = CHAIN_KEY_SIZE;
	conversation->has_receive_chain_key = true;
	//purported receive chain key
	if (this->storage->purported_receive_chain_key.contains(CHAIN_KEY_SIZE)) {
		conversation->purported_receive_chain_key.data = throwing_zeroed_malloc<unsigned char>(CHAIN_KEY_SIZE);
		if (this->storage->purported_receive_chain_key.cloneToRaw(conversation->purported_receive_chain_key.data, CHAIN_KEY_SIZE) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported receive chain key.");
		}
		conversation->purported_receive_chain_key.len = CHAIN_KEY_SIZE;
		conversation->has_purported_receive_chain_key = true;
	}

	//identity key
	//our public identity key
	if (!this->storage->our_public_identity.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "our_public_identity missing or has an invalid size.");
	}
	conversation->our_public_identity_key.data = throwing_zeroed_malloc<unsigned char>(PUBLIC_KEY_SIZE);
	if (this->storage->our_public_identity.cloneToRaw(conversation->our_public_identity_key.data, PUBLIC_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	conversation->our_public_identity_key.len = PUBLIC_KEY_SIZE;
	conversation->has_our_public_identity_key = true;
	//their public identity key
	if (!this->storage->their_public_identity.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "their_public_identity missing or has an invalid size.");
	}
	conversation->their_public_identity_key.data = throwing_zeroed_malloc<unsigned char>(PUBLIC_KEY_SIZE);
	if (this->storage->their_public_identity.cloneToRaw(conversation->their_public_identity_key.data, PUBLIC_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public identity key.");
	}
	conversation->their_public_identity_key.len = PUBLIC_KEY_SIZE;
	conversation->has_their_public_identity_key = true;

	//ephemeral keys
	//our private ephemeral key
	if (!this->storage->our_private_ephemeral.contains(PRIVATE_KEY_SIZE)) {
		throw MolchException(EXPORT_ERROR, "our_private_ephemeral missing or has an invalid size.");
	}
	conversation->our_private_ephemeral_key.data = throwing_zeroed_malloc<unsigned char>(PRIVATE_KEY_SIZE);
	if (this->storage->our_private_ephemeral.cloneToRaw(conversation->our_private_ephemeral_key.data, PRIVATE_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	conversation->our_private_ephemeral_key.len = PRIVATE_KEY_SIZE;
	conversation->has_our_private_ephemeral_key = true;
	//our public ephemeral key
	if (!this->storage->our_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(BUFFER_ERROR, "our_public_ephemeral missing or has an invalid size.");
	}
	conversation->our_public_ephemeral_key.data = throwing_zeroed_malloc<unsigned char>(PUBLIC_KEY_SIZE);
	if (this->storage->our_public_ephemeral.cloneToRaw(conversation->our_public_ephemeral_key.data, PUBLIC_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	conversation->our_public_ephemeral_key.len = PUBLIC_KEY_SIZE;
	conversation->has_our_public_ephemeral_key = true;
	//their public ephemeral key
	if (!this->storage->their_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(BUFFER_ERROR, "their_public_ephemeral missing or has an invalid size.");
	}
	conversation->their_public_ephemeral_key.data = throwing_zeroed_malloc<unsigned char>(PUBLIC_KEY_SIZE);
	if (this->storage->their_public_ephemeral.cloneToRaw(conversation->their_public_ephemeral_key.data, PUBLIC_KEY_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	conversation->their_public_ephemeral_key.len = PUBLIC_KEY_SIZE;
	conversation->has_their_public_ephemeral_key = true;
	//their purported public ephemeral key
	if (this->storage->their_purported_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		conversation->their_purported_public_ephemeral.data = throwing_zeroed_malloc<unsigned char>(PUBLIC_KEY_SIZE);
		if (this->storage->their_purported_public_ephemeral.cloneToRaw(conversation->their_purported_public_ephemeral.data, PUBLIC_KEY_SIZE) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
		}
		conversation->their_purported_public_ephemeral.len = PUBLIC_KEY_SIZE;
		conversation->has_their_purported_public_ephemeral = true;
	}

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
			throw MolchException(INVALID_VALUE, "Invalid value of ratchet->header_decryptable.");
	}

	//keystores
	//skipped header and message keystore
	this->skipped_header_and_message_keys.exportProtobuf(
		conversation->skipped_header_and_message_keys,
		conversation->n_skipped_header_and_message_keys);
	//staged header and message keystore
	this->staged_header_and_message_keys.exportProtobuf(
			conversation->staged_header_and_message_keys,
			conversation->n_staged_header_and_message_keys);

	return conversation;
}

Ratchet::Ratchet(const Conversation& conversation) {
	this->init();

	//import all the stuff
	//message numbers
	//send message number
	if (!conversation.has_send_message_number) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct.");
	}
	this->send_message_number = conversation.send_message_number;
	//receive message number
	if (!conversation.has_receive_message_number) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct.");
	}
	this->receive_message_number = conversation.receive_message_number;
	//purported message number
	if (!conversation.has_purported_message_number) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct.");
	}
	this->purported_message_number = conversation.purported_message_number;
	//previous message number
	if (!conversation.has_previous_message_number) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct.");
	}
	this->previous_message_number = conversation.previous_message_number;
	//purported previous message number
	if (!conversation.has_purported_previous_message_number) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct.");
	}
	this->purported_previous_message_number = conversation.purported_previous_message_number;


	//flags
	//ratchet flag
	if (!conversation.has_ratchet_flag) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct.");
	}
	this->ratchet_flag = conversation.ratchet_flag;
	//am I Alice
	if (!conversation.has_am_i_alice) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct.");
	}
	this->am_i_alice = conversation.am_i_alice;
	//received valid
	if (!conversation.has_received_valid) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct.");
	}
	this->received_valid = conversation.received_valid;


	//header decryptable
	if (!conversation.has_header_decryptable) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct.");
	}
	switch (conversation.header_decryptable) {
		case CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE:
			this->header_decryptable = CURRENT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE:
			this->header_decryptable = NEXT_DECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE:
			this->header_decryptable = UNDECRYPTABLE;
			break;

		case CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED:
			this->header_decryptable = NOT_TRIED;
			break;

		default:
			throw MolchException(INVALID_VALUE, "header_decryptable has an invalid value.");
	}

	//root keys
	//root key
	if (!conversation.has_root_key || (conversation.root_key.len != ROOT_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "root_key is missing from protobuf.");
	}
	if (this->storage->root_key.cloneFromRaw(conversation.root_key.data, conversation.root_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy root key.");
	}
	//purported root key
	if (conversation.has_purported_root_key && (conversation.purported_root_key.len == ROOT_KEY_SIZE)) {
			if (this->storage->purported_root_key.cloneFromRaw(conversation.purported_root_key.data, conversation.purported_root_key.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported root key.");
		}
	}

	//header key
	//send header key
	if (!this->am_i_alice
			&& (!conversation.has_send_header_key || (conversation.send_header_key.len != HEADER_KEY_SIZE))) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "send_header_key is missing from the protobuf.");
	}
	if (this->storage->send_header_key.cloneFromRaw(conversation.send_header_key.data, conversation.send_header_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy send header key.");
	}
	//receive header key
	if (this->am_i_alice &&
			(!conversation.has_receive_header_key || (conversation.receive_header_key.len != HEADER_KEY_SIZE))) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "receive_header_key is missing from protobuf.");
	}
	if (this->storage->receive_header_key.cloneFromRaw(conversation.receive_header_key.data, conversation.receive_header_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy receive header key.");
	}
	//next send header key
	if (!conversation.has_next_send_header_key || (conversation.next_send_header_key.len != HEADER_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "next_send_header_key is missing from protobuf.");
	}
	if (this->storage->next_send_header_key.cloneFromRaw(conversation.next_send_header_key.data, conversation.next_send_header_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy next send header key.");
	}
	//next receive header key
	if (!conversation.has_next_receive_header_key || (conversation.next_receive_header_key.len != HEADER_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "next_receive_header_key is missing from protobuf.");
	}
	if (this->storage->next_receive_header_key.cloneFromRaw(conversation.next_receive_header_key.data, conversation.next_receive_header_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy next receive header key.");
	}
	//purported receive header key
	if (conversation.has_purported_receive_header_key && (conversation.purported_receive_header_key.len == HEADER_KEY_SIZE)) {
		if (this->storage->purported_receive_header_key.cloneFromRaw(conversation.purported_receive_header_key.data, conversation.purported_receive_header_key.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported receive header key.");
		}
	}
	//purported next receive header key
	if (conversation.has_purported_next_receive_header_key && (conversation.purported_next_receive_header_key.len == HEADER_KEY_SIZE)) {
		if (this->storage->purported_next_receive_header_key.cloneFromRaw(conversation.purported_next_receive_header_key.data, conversation.purported_next_receive_header_key.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported next receive header key.");
		}
	}

	//chain keys
	//send chain key
	if (!this->am_i_alice &&
			(!conversation.has_send_chain_key || (conversation.send_chain_key.len != CHAIN_KEY_SIZE))) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "send_chain_key is missing from the potobuf.");
	}
	if (this->storage->send_chain_key.cloneFromRaw(conversation.send_chain_key.data, conversation.send_chain_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy send chain key.");
	}
	//receive chain key
	if (this->am_i_alice &&
			(!conversation.has_receive_chain_key || (conversation.receive_chain_key.len != CHAIN_KEY_SIZE))) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "receive_chain_key is missing from the protobuf.");
	}
	if (this->storage->receive_chain_key.cloneFromRaw(conversation.receive_chain_key.data, conversation.receive_chain_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy receive chain key.");
	}
	//purported receive chain key
	if (conversation.has_purported_receive_chain_key && (conversation.purported_receive_chain_key.len == CHAIN_KEY_SIZE)) {
		if (this->storage->purported_receive_chain_key.cloneFromRaw(conversation.purported_receive_chain_key.data, conversation.purported_receive_chain_key.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy purported receive chain key.");
		}
	}

	//identity key
	//our public identity key
	if (!conversation.has_our_public_identity_key || (conversation.our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "our_public_identity_key is missing from the protobuf.");
	}
	if (this->storage->our_public_identity.cloneFromRaw(conversation.our_public_identity_key.data, conversation.our_public_identity_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public identity key.");
	}
	//their public identity key
	if (!conversation.has_their_public_identity_key || (conversation.their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "their_public_identity is missing from the protobuf.");
	}
	if (this->storage->their_public_identity.cloneFromRaw(conversation.their_public_identity_key.data, conversation.their_public_identity_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public identity key.");
	}

	//ephemeral keys
	//our private ephemeral key
	if (!conversation.has_our_private_ephemeral_key || (conversation.our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "our_private_ephemral is missing from the protobuf.");
	}
	if (this->storage->our_private_ephemeral.cloneFromRaw(conversation.our_private_ephemeral_key.data, conversation.our_private_ephemeral_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our private ephemeral key.");
	}
	//our public ephemeral key
	if (!conversation.has_our_public_ephemeral_key || (conversation.our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "our_public_ephemeral is missing from the protobuf.");
	}
	if (this->storage->our_public_ephemeral.cloneFromRaw(conversation.our_public_ephemeral_key.data, conversation.our_public_ephemeral_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy our public ephemeral key.");
	}
	//their public ephemeral key
	if (!conversation.has_their_public_ephemeral_key || (conversation.their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "their_public_ephemeral is missing from the protobuf.");
	}
	if (this->storage->their_public_ephemeral.cloneFromRaw(conversation.their_public_ephemeral_key.data, conversation.their_public_ephemeral_key.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy their public ephemeral key.");
	}
	//their purported public ephemeral key
	if (conversation.has_their_purported_public_ephemeral && (conversation.their_purported_public_ephemeral.len == PUBLIC_KEY_SIZE)) {
		if (this->storage->their_purported_public_ephemeral.cloneFromRaw(conversation.their_purported_public_ephemeral.data, conversation.their_purported_public_ephemeral.len) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy their purported public ephemeral key.");
		}
	}

	//header and message keystores
	//skipped header and message keys
	this->skipped_header_and_message_keys = HeaderAndMessageKeyStore(
			conversation.skipped_header_and_message_keys,
			conversation.n_skipped_header_and_message_keys);
	//staged heeader and message keys
	this->staged_header_and_message_keys = HeaderAndMessageKeyStore(
			conversation.staged_header_and_message_keys,
			conversation.n_staged_header_and_message_keys);
}

std::ostream& Ratchet::print(std::ostream& stream) const {
	//root keys
	stream << "Root key:\n";
	stream << this->storage->root_key.toHex() << '\n';
	stream << "Purported root key:\n";
	stream << this->storage->purported_root_key.toHex() << '\n';

	//header keys
	stream << "Send header key:\n";
	stream << this->storage->send_header_key.toHex() << '\n';
	stream << "Receive header key:\n";
	stream << this->storage->receive_header_key.toHex() << '\n';
	stream << "Next send header key:\n";
	stream << this->storage->next_send_header_key.toHex() << '\n';
	stream << "Next receive header key:\n";
	stream << this->storage->next_receive_header_key.toHex() << '\n';
	stream << "Purported receive header key:\n";
	stream << this->storage->purported_receive_header_key.toHex() << '\n';
	stream << "Purported next receive header key:\n";
	stream << this->storage->purported_next_receive_header_key.toHex() << '\n';

	//chain keys
	stream << "Send chain key:\n";
	stream << this->storage->send_chain_key.toHex() << '\n';
	stream << "Receive chain key:\n";
	stream << this->storage->receive_chain_key.toHex() << '\n';
	stream << "Purported receive chain key:\n";
	stream << this->storage->purported_receive_chain_key.toHex() << '\n';

	//identity keys
	stream << "Our public identity key:\n";
	stream << this->storage->our_public_identity.toHex() << '\n';
	stream << "Their public identity key:\n";
	stream << this->storage->their_public_identity.toHex() << '\n';

	//ephemeral keys
	stream << "Our private ephemeral key:\n";
	stream << this->storage->our_private_ephemeral.toHex() << '\n';
	stream << "Our public ephemeral key:\n";
	stream << this->storage->our_public_ephemeral.toHex() << '\n';
	stream << "Their public ephemeral key:\n";
	stream << this->storage->their_public_ephemeral.toHex() << '\n';
	stream << "Their purported public ephemeral key:\n";
	stream << this->storage->their_purported_public_ephemeral.toHex() << '\n';

	//numbers
	stream << "Send message number: " << this->send_message_number << '\n';
	stream << "Receive message number: " << this->receive_message_number << '\n';
	stream << "Purported message number: " << this->purported_message_number << '\n';
	stream << "Previous message number: " << this->previous_message_number << '\n';
	stream << "Purported previous message number: " << this->purported_previous_message_number << '\n';

	//others
	stream << "Ratchet flag: " << this->ratchet_flag << '\n';
	stream << "Am I Alice: " << this->am_i_alice << '\n';
	stream << "Received valid: " << this->received_valid << '\n';
	stream << "Header decryptability: " << static_cast<unsigned int>(this->header_decryptable) << '\n';

	//header and message keystores
	stream << "Skipped header and message keys:\n";
	this->skipped_header_and_message_keys.print(stream) << '\n';
	stream << "Staged header and message keys:\n";
	this->staged_header_and_message_keys.print(stream) << '\n';

	return stream;
}

