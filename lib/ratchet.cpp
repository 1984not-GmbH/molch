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

namespace Molch {
	void Ratchet::init() {
		this->storage = std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>>(throwing_sodium_malloc<RatchetStorage>(1));
		new (this->storage.get()) RatchetStorage{};
	}

	/*
	 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
	 *
	 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
	 * immediately deleted after deriving the initial root key though!)
	 */
	Ratchet::Ratchet(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral) {
		//check buffer sizes
		if (our_private_identity.empty
				|| our_public_identity.empty
				|| their_public_identity.empty
				|| our_private_ephemeral.empty
				|| our_public_ephemeral.empty
				|| their_public_ephemeral.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to ratchet_create.");
		}

		this->init();

		//find out if we are alice by comparing both public keys
		//the one with the bigger public key is alice
		this->role = [&our_public_identity, &their_public_identity] () {
			if (our_public_identity > their_public_identity) {
				return Role::ALICE;
			} else if (our_public_identity < their_public_identity) {
				return Role::BOB;
			} else {
				throw Exception(SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
			}
		}();

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
			this->role);

		//copy keys into state
		//our public identity
		this->storage->our_public_identity = our_public_identity;
		//their_public_identity
		this->storage->their_public_identity = their_public_identity;
		//our_private_ephemeral
		this->storage->our_private_ephemeral = our_private_ephemeral;
		//our_public_ephemeral
		this->storage->our_public_ephemeral = our_public_ephemeral;
		//their_public_ephemeral
		this->storage->their_public_ephemeral = their_public_ephemeral;

		//set other state
		this->ratchet_flag = static_cast<bool>(this->role);
		this->received_valid = true; //allowing the receival of new messages
		this->header_decryptable = HeaderDecryptability::NOT_TRIED;
		this->send_message_number = 0;
		this->receive_message_number = 0;
		this->previous_message_number = 0;
	}

	/*
	 * Get keys and metadata to send the next message.
	 */
	void Ratchet::send(
			HeaderKey& send_header_key, //HEADER_KEY_SIZE, HKs
			uint32_t& send_message_number, //Ns
			uint32_t& previous_send_message_number, //PNs
			PublicKey& our_public_ephemeral, //PUBLIC_KEY_SIZE, DHRs
			MessageKey& message_key) { //MESSAGE_KEY_SIZE, MK
		if (this->ratchet_flag) {
			//DHRs = generateECDH()
			auto status{crypto_box_keypair(
					this->storage->our_public_ephemeral.data(),
					this->storage->our_private_ephemeral.data())};
			if (status != 0) {
				throw Exception(KEYGENERATION_FAILED, "Failed to generate new ephemeral keypair.");
			}
			this->storage->our_public_ephemeral.empty = false;
			this->storage->our_private_ephemeral.empty = false;

			//HKs = NHKs
			this->storage->send_header_key = this->storage->next_send_header_key;

			//clone the root key for it to not be overwritten in the next step
			RootKey root_key_backup{this->storage->root_key};

			//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
			derive_root_next_header_and_chain_keys(
				this->storage->root_key,
				this->storage->next_send_header_key,
				this->storage->send_chain_key,
				this->storage->our_private_ephemeral,
				this->storage->our_public_ephemeral,
				this->storage->their_public_ephemeral,
				root_key_backup,
				this->role);

			//PNs = Ns
			this->previous_message_number = this->send_message_number;

			//Ns = 0
			this->send_message_number = 0;

			//ratchet_flag = False
			this->ratchet_flag = false;
		}

		//MK = HMAC-HASH(CKs, "0")
		message_key = this->storage->send_chain_key.deriveMessageKey();

		//copy the other data to the output
		//(corresponds to
		//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
		//  in the axolotl specification)
		//HKs:
		send_header_key = this->storage->send_header_key;
		//Ns
		send_message_number = this->send_message_number;
		//PNs
		previous_send_message_number = this->previous_message_number;
		//DHRs
		our_public_ephemeral = this->storage->our_public_ephemeral;

		//Ns = Ns + 1
		this->send_message_number++;

		//clone the chain key for it to not be overwritten in the next step
		ChainKey chain_key_backup{this->storage->send_chain_key};

		//CKs = HMAC-HASH(CKs, "1")
		this->storage->send_chain_key = chain_key_backup.deriveChainKey();
	}

	/*
	 * Get a copy of the current and the next receive header key.
	 */
	void Ratchet::getReceiveHeaderKeys(
			HeaderKey& current_receive_header_key,
			HeaderKey& next_receive_header_key) const {
		//clone the header keys
		current_receive_header_key = this->storage->receive_header_key;
		next_receive_header_key = this->storage->next_receive_header_key;
	}

	/*
	 * Set if the header is decryptable with the current (state->receive_header_key)
	 * or next (next_receive_header_key) header key, or isn't decryptable.
	 */
	void Ratchet::setHeaderDecryptability(const HeaderDecryptability header_decryptable) {
		if (this->header_decryptable != HeaderDecryptability::NOT_TRIED) {
			//if the last message hasn't been properly handled yet, abort
			throw Exception(GENERIC_ERROR, "Message hasn't been handled yet.");
		}

		if (header_decryptable == HeaderDecryptability::NOT_TRIED) {
			//can't set to "NOT_TRIED"
			throw Exception(INVALID_INPUT, "Can't set to \"NOT_TRIED\"");
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
			ChainKey * const output_chain_key, //output, optional CHAIN_KEY_SIZE
			MessageKey * const output_message_key, //output, optional MESSAGE_KEY_SIZE
			const HeaderKey& current_header_key,
			const uint32_t current_message_number,
			const uint32_t future_message_number,
			const ChainKey& chain_key) {
		//when chain key is <none>, do nothing
		if (chain_key.isNone()) {
			return;
		}

		//set current_chain_key to chain key to initialize it for the calculation that's
		//following
		ChainKey current_chain_key{chain_key};

		ChainKey next_chain_key;
		MessageKey current_message_key;
		for (uint32_t pos{current_message_number}; pos < future_message_number; pos++) {
			current_message_key = current_chain_key.deriveMessageKey();
			staging_area.add(current_header_key, current_message_key);
			next_chain_key = current_chain_key.deriveChainKey();

			//shift chain keys
			current_chain_key = next_chain_key;
		}

		//derive the message key that will be returned
		if (output_message_key != nullptr) {
			*output_message_key = current_chain_key.deriveMessageKey();
		}

		//derive the chain key that will be returned
		if (output_chain_key != nullptr) {
			*output_chain_key = current_chain_key.deriveChainKey();
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
			MessageKey& message_key,
			const PublicKey& their_purported_public_ephemeral,
			const uint32_t purported_message_number,
			const uint32_t purported_previous_message_number) {
		//check input
		if (their_purported_public_ephemeral.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to ratchet_receive.");
		}

		if (!this->received_valid) {
			//abort because the previously received message hasn't been verified yet.
			throw Exception(INVALID_STATE, "Previously received message hasn't been verified yet.");
		}

		//header decryption hasn't been tried yet
		if (this->header_decryptable == HeaderDecryptability::NOT_TRIED) {
			throw Exception(INVALID_STATE, "Header decryption hasn't been tried yet.");
		}

		if (!this->storage->receive_header_key.isNone() && (this->header_decryptable == HeaderDecryptability::CURRENT_DECRYPTABLE)) { //still the same message chain
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
			if (this->ratchet_flag || (this->header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				throw Exception(DECRYPT_ERROR, "Undecryptable.");
			}

			//Np = read(): get the purported message number from the input
			this->purported_message_number = purported_message_number;
			//PNp = read(): get the purported previous message number from the input
			this->purported_previous_message_number = purported_previous_message_number;
			//DHRp = read(): get the purported ephemeral from the input
			this->storage->their_purported_public_ephemeral = their_purported_public_ephemeral;

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
			this->storage->purported_receive_header_key = this->storage->next_receive_header_key;

			//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
			derive_root_next_header_and_chain_keys(
					this->storage->purported_root_key,
					this->storage->purported_next_receive_header_key,
					this->storage->purported_receive_chain_key,
					this->storage->our_private_ephemeral,
					this->storage->our_public_ephemeral,
					their_purported_public_ephemeral,
					this->storage->root_key,
					this->role);

			//backup the purported chain key because it will get overwritten in the next step
			ChainKey purported_chain_key_backup{this->storage->purported_receive_chain_key};

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
		auto header_decryptable{this->header_decryptable};
		this->header_decryptable = HeaderDecryptability::NOT_TRIED;

		if (!valid) { //message couldn't be decrypted
			this->staged_header_and_message_keys.keys.clear();
			return;
		}

		if (this->storage->receive_header_key.isNone() || (header_decryptable != HeaderDecryptability::CURRENT_DECRYPTABLE)) { //new message chain
			if (this->ratchet_flag || (header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				//if ratchet_flag or not Dec(NHKr, header)
				//clear purported message and header keys
				this->staged_header_and_message_keys.keys.clear();
				return;
			}

			//otherwise, received message was valid
			//accept purported values
			//RK = RKp
			this->storage->root_key = this->storage->purported_root_key;
			//HKr = HKp
			this->storage->receive_header_key = this->storage->purported_receive_header_key;
			//NHKr = NHKp
			this->storage->next_receive_header_key = this->storage->purported_next_receive_header_key;
			//DHRr = DHRp
			this->storage->their_public_ephemeral = this->storage->their_purported_public_ephemeral;
			//erase(DHRs)
			this->storage->our_private_ephemeral.clear();
			//TODO: Get rid of this somedeay
			this->storage->our_private_ephemeral.empty = false;
			//ratchet_flag = True
			this->ratchet_flag = true;
		}

		//commit_skipped_header_and_message_keys
		this->commitSkippedHeaderAndMessageKeys();
		//Nr = Np + 1
		this->receive_message_number = this->purported_message_number + 1;
		//CKr = CKp
		this->storage->receive_chain_key = this->storage->purported_receive_chain_key;
	}

	ProtobufCConversation* Ratchet::exportProtobuf(ProtobufPool& pool) const {
		auto conversation{pool.allocate<ProtobufCConversation>(1)};
		conversation__init(conversation);

		//root keys
		//root key
		if (this->storage->root_key.empty) {
			throw Exception(EXPORT_ERROR, "root_key is missing or has an incorrect size.");
		}
		conversation->root_key.data = pool.allocate<unsigned char>(ROOT_KEY_SIZE);
		this->storage->root_key.copyTo(conversation->root_key.data, ROOT_KEY_SIZE);
		conversation->root_key.len = ROOT_KEY_SIZE;
		conversation->has_root_key = true;
		//purported root key
		if (!this->storage->purported_root_key.empty) {
			conversation->purported_root_key.data = pool.allocate<unsigned char>(ROOT_KEY_SIZE);
			this->storage->purported_root_key.copyTo(conversation->purported_root_key.data, ROOT_KEY_SIZE);
			conversation->purported_root_key.len = ROOT_KEY_SIZE;
			conversation->has_purported_root_key = true;
		}

		//header keys
		//send header key
		if ((this->role == Role::BOB) && this->storage->send_header_key.empty) {
			throw Exception(EXPORT_ERROR, "send_header_key missing or has an incorrect size.");
		}
		conversation->send_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
		this->storage->send_header_key.copyTo(conversation->send_header_key.data, HEADER_KEY_SIZE);
		conversation->send_header_key.len = HEADER_KEY_SIZE;
		conversation->has_send_header_key = true;
		//receive header key
		if ((this->role == Role::ALICE) && this->storage->receive_header_key.empty) {
			throw Exception(EXPORT_ERROR, "receive_header_key missing or has an incorrect size.");
		}
		conversation->receive_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
		this->storage->receive_header_key.copyTo(conversation->receive_header_key.data, HEADER_KEY_SIZE);
		conversation->receive_header_key.len = HEADER_KEY_SIZE;
		conversation->has_receive_header_key = true;
		//next send header key
		if (this->storage->next_send_header_key.empty) {
			throw Exception(EXPORT_ERROR, "next_send_header_key missing or has incorrect size.");
		}
		conversation->next_send_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
		this->storage->next_send_header_key.copyTo(conversation->next_send_header_key.data, HEADER_KEY_SIZE);
		conversation->next_send_header_key.len = HEADER_KEY_SIZE;
		conversation->has_next_send_header_key = true;
		//next receive header key
		if (this->storage->next_receive_header_key.empty) {
			throw Exception(EXPORT_ERROR, "next_receive_header_key missinge or has an incorrect size.");
		}
		conversation->next_receive_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
		this->storage->next_receive_header_key.copyTo(conversation->next_receive_header_key.data, HEADER_KEY_SIZE);
		conversation->next_receive_header_key.len = HEADER_KEY_SIZE;
		conversation->has_next_receive_header_key = true;
		//purported receive header key
		if (!this->storage->purported_receive_header_key.empty) {
			conversation->purported_receive_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
			this->storage->purported_receive_header_key.copyTo(conversation->purported_receive_header_key.data, HEADER_KEY_SIZE);
			conversation->purported_receive_header_key.len = HEADER_KEY_SIZE;
			conversation->has_purported_receive_header_key = true;
		}
		//purported next receive header key
		if (!this->storage->purported_next_receive_header_key.empty) {
			conversation->purported_next_receive_header_key.data = pool.allocate<unsigned char>(HEADER_KEY_SIZE);
			this->storage->purported_next_receive_header_key.copyTo(conversation->purported_next_receive_header_key.data, HEADER_KEY_SIZE);
			conversation->purported_next_receive_header_key.len = HEADER_KEY_SIZE;
			conversation->has_purported_next_receive_header_key = true;
		}

		//chain keys
		//send chain key
		if ((this->role == Role::BOB) && this->storage->send_chain_key.empty) {
			throw Exception(EXPORT_ERROR, "send_chain_key missing or has an invalid size.");
		}
		conversation->send_chain_key.data = pool.allocate<unsigned char>(CHAIN_KEY_SIZE);
		this->storage->send_chain_key.copyTo(conversation->send_chain_key.data, CHAIN_KEY_SIZE);
		conversation->send_chain_key.len = CHAIN_KEY_SIZE;
		conversation->has_send_chain_key = true;
		//receive chain key
		if ((this->role == Role::ALICE) && this->storage->receive_chain_key.empty) {
			throw Exception(EXPORT_ERROR, "receive_chain_key missing or has an incorrect size.");
		}
		conversation->receive_chain_key.data = pool.allocate<unsigned char>(CHAIN_KEY_SIZE);
		this->storage->receive_chain_key.copyTo(conversation->receive_chain_key.data, CHAIN_KEY_SIZE);
		conversation->receive_chain_key.len = CHAIN_KEY_SIZE;
		conversation->has_receive_chain_key = true;
		//purported receive chain key
		if (!this->storage->purported_receive_chain_key.empty) {
			conversation->purported_receive_chain_key.data = pool.allocate<unsigned char>(CHAIN_KEY_SIZE);
			this->storage->purported_receive_chain_key.copyTo(conversation->purported_receive_chain_key.data, CHAIN_KEY_SIZE);
			conversation->purported_receive_chain_key.len = CHAIN_KEY_SIZE;
			conversation->has_purported_receive_chain_key = true;
		}

		//identity key
		//our public identity key
		if (this->storage->our_public_identity.empty) {
			throw Exception(EXPORT_ERROR, "our_public_identity missing or has an invalid size.");
		}
		conversation->our_public_identity_key.data = pool.allocate<unsigned char>(PUBLIC_KEY_SIZE);
		this->storage->our_public_identity.copyTo(conversation->our_public_identity_key.data, PUBLIC_KEY_SIZE);
		conversation->our_public_identity_key.len = PUBLIC_KEY_SIZE;
		conversation->has_our_public_identity_key = true;
		//their public identity key
		if (this->storage->their_public_identity.empty) {
			throw Exception(EXPORT_ERROR, "their_public_identity missing or has an invalid size.");
		}
		conversation->their_public_identity_key.data = pool.allocate<unsigned char>(PUBLIC_KEY_SIZE);
		this->storage->their_public_identity.copyTo(conversation->their_public_identity_key.data, PUBLIC_KEY_SIZE);
		conversation->their_public_identity_key.len = PUBLIC_KEY_SIZE;
		conversation->has_their_public_identity_key = true;

		//ephemeral keys
		//our private ephemeral key
		if (this->storage->our_private_ephemeral.empty) {
			throw Exception(EXPORT_ERROR, "our_private_ephemeral missing or has an invalid size.");
		}
		conversation->our_private_ephemeral_key.data = pool.allocate<unsigned char>(PRIVATE_KEY_SIZE);
		this->storage->our_private_ephemeral.copyTo(conversation->our_private_ephemeral_key.data, PRIVATE_KEY_SIZE);
		conversation->our_private_ephemeral_key.len = PRIVATE_KEY_SIZE;
		conversation->has_our_private_ephemeral_key = true;
		//our public ephemeral key
		if (this->storage->our_public_ephemeral.empty) {
			throw Exception(BUFFER_ERROR, "our_public_ephemeral missing or has an invalid size.");
		}
		conversation->our_public_ephemeral_key.data = pool.allocate<unsigned char>(PUBLIC_KEY_SIZE);
		this->storage->our_public_ephemeral.copyTo(conversation->our_public_ephemeral_key.data, PUBLIC_KEY_SIZE);
		conversation->our_public_ephemeral_key.len = PUBLIC_KEY_SIZE;
		conversation->has_our_public_ephemeral_key = true;
		//their public ephemeral key
		if (this->storage->their_public_ephemeral.empty) {
			throw Exception(BUFFER_ERROR, "their_public_ephemeral missing or has an invalid size.");
		}
		conversation->their_public_ephemeral_key.data = pool.allocate<unsigned char>(PUBLIC_KEY_SIZE);
		this->storage->their_public_ephemeral.copyTo(conversation->their_public_ephemeral_key.data, PUBLIC_KEY_SIZE);
		conversation->their_public_ephemeral_key.len = PUBLIC_KEY_SIZE;
		conversation->has_their_public_ephemeral_key = true;
		//their purported public ephemeral key
		if (!this->storage->their_purported_public_ephemeral.empty) {
			conversation->their_purported_public_ephemeral.data = pool.allocate<unsigned char>(PUBLIC_KEY_SIZE);
			this->storage->their_purported_public_ephemeral.copyTo(conversation->their_purported_public_ephemeral.data, PUBLIC_KEY_SIZE);
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
		conversation->am_i_alice = static_cast<bool>(this->role);
		//received valid
		conversation->has_received_valid = true;
		conversation->received_valid = this->received_valid;

		//header decryptability
		conversation->has_header_decryptable = false;
		conversation->header_decryptable = [&] () {
				switch (this->header_decryptable) {
					case HeaderDecryptability::CURRENT_DECRYPTABLE:
						return CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE;

					case HeaderDecryptability::NEXT_DECRYPTABLE:
						return CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE;

					case HeaderDecryptability::UNDECRYPTABLE:
						return CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE;

					case HeaderDecryptability::NOT_TRIED:
						return CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED;

					default:
						throw Exception(INVALID_VALUE, "Invalid value of ratchet->header_decryptable.");
			}
		}();
		conversation->has_header_decryptable = true;

		//keystores
		//skipped header and message keystore
		this->skipped_header_and_message_keys.exportProtobuf(
			pool,
			conversation->skipped_header_and_message_keys,
			conversation->n_skipped_header_and_message_keys);
		//staged header and message keystore
		this->staged_header_and_message_keys.exportProtobuf(
			pool,
			conversation->staged_header_and_message_keys,
			conversation->n_staged_header_and_message_keys);

		return conversation;
	}

	Ratchet::Ratchet(const ProtobufCConversation& conversation) {
		this->init();

		//import all the stuff
		//message numbers
		//send message number
		if (!conversation.has_send_message_number) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct.");
		}
		this->send_message_number = conversation.send_message_number;
		//receive message number
		if (!conversation.has_receive_message_number) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct.");
		}
		this->receive_message_number = conversation.receive_message_number;
		//purported message number
		if (!conversation.has_purported_message_number) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct.");
		}
		this->purported_message_number = conversation.purported_message_number;
		//previous message number
		if (!conversation.has_previous_message_number) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct.");
		}
		this->previous_message_number = conversation.previous_message_number;
		//purported previous message number
		if (!conversation.has_purported_previous_message_number) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct.");
		}
		this->purported_previous_message_number = conversation.purported_previous_message_number;


		//flags
		//ratchet flag
		if (!conversation.has_ratchet_flag) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct.");
		}
		this->ratchet_flag = conversation.ratchet_flag;
		//am I Alice
		if (!conversation.has_am_i_alice) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct.");
		}
		this->role = static_cast<Role>(conversation.am_i_alice);
		//received valid
		if (!conversation.has_received_valid) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct.");
		}
		this->received_valid = conversation.received_valid;


		//header decryptable
		if (!conversation.has_header_decryptable) {
			throw Exception(PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct.");
		}
		this->header_decryptable = [&] () {
			switch (conversation.header_decryptable) {
				case CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE:
					return HeaderDecryptability::CURRENT_DECRYPTABLE;

				case CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE:
					return HeaderDecryptability::NEXT_DECRYPTABLE;

				case CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE:
					return HeaderDecryptability::UNDECRYPTABLE;

				case CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED:
					return HeaderDecryptability::NOT_TRIED;

				default:
					throw Exception(INVALID_VALUE, "header_decryptable has an invalid value.");
			}
		}();

		//root keys
		//root key
		if (!conversation.has_root_key || (conversation.root_key.len != ROOT_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "root_key is missing from protobuf.");
		}
		this->storage->root_key.set(conversation.root_key.data, conversation.root_key.len);
		//purported root key
		if (conversation.has_purported_root_key && (conversation.purported_root_key.len == ROOT_KEY_SIZE)) {
			this->storage->purported_root_key.set(conversation.purported_root_key.data, conversation.purported_root_key.len);
		}

		//header key
		//send header key
		if ((this->role == Role::BOB)
				&& (!conversation.has_send_header_key || (conversation.send_header_key.len != HEADER_KEY_SIZE))) {
			throw Exception(PROTOBUF_MISSING_ERROR, "send_header_key is missing from the protobuf.");
		}
		this->storage->send_header_key.set(conversation.send_header_key.data, conversation.send_header_key.len);
		//receive header key
		if ((this->role == Role::ALICE) &&
				(!conversation.has_receive_header_key || (conversation.receive_header_key.len != HEADER_KEY_SIZE))) {
			throw Exception(PROTOBUF_MISSING_ERROR, "receive_header_key is missing from protobuf.");
		}
		this->storage->receive_header_key.set(conversation.receive_header_key.data, conversation.receive_header_key.len);
		//next send header key
		if (!conversation.has_next_send_header_key || (conversation.next_send_header_key.len != HEADER_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "next_send_header_key is missing from protobuf.");
		}
		this->storage->next_send_header_key.set(conversation.next_send_header_key.data, conversation.next_send_header_key.len);
		//next receive header key
		if (!conversation.has_next_receive_header_key || (conversation.next_receive_header_key.len != HEADER_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "next_receive_header_key is missing from protobuf.");
		}
		this->storage->next_receive_header_key.set(conversation.next_receive_header_key.data, conversation.next_receive_header_key.len);
		//purported receive header key
		if (conversation.has_purported_receive_header_key && (conversation.purported_receive_header_key.len == HEADER_KEY_SIZE)) {
			this->storage->purported_receive_header_key.set(conversation.purported_receive_header_key.data, conversation.purported_receive_header_key.len);
		}
		//purported next receive header key
		if (conversation.has_purported_next_receive_header_key && (conversation.purported_next_receive_header_key.len == HEADER_KEY_SIZE)) {
			this->storage->purported_next_receive_header_key.set(conversation.purported_next_receive_header_key.data, conversation.purported_next_receive_header_key.len);
		}

		//chain keys
		//send chain key
		if ((this->role == Role::BOB) &&
				(!conversation.has_send_chain_key || (conversation.send_chain_key.len != CHAIN_KEY_SIZE))) {
			throw Exception(PROTOBUF_MISSING_ERROR, "send_chain_key is missing from the potobuf.");
		}
		this->storage->send_chain_key.set(conversation.send_chain_key.data, conversation.send_chain_key.len);
		//receive chain key
		if ((this->role == Role::ALICE) &&
				(!conversation.has_receive_chain_key || (conversation.receive_chain_key.len != CHAIN_KEY_SIZE))) {
			throw Exception(PROTOBUF_MISSING_ERROR, "receive_chain_key is missing from the protobuf.");
		}
		this->storage->receive_chain_key.set(conversation.receive_chain_key.data, conversation.receive_chain_key.len);
		//purported receive chain key
		if (conversation.has_purported_receive_chain_key && (conversation.purported_receive_chain_key.len == CHAIN_KEY_SIZE)) {
			this->storage->purported_receive_chain_key.set(conversation.purported_receive_chain_key.data, conversation.purported_receive_chain_key.len);
		}

		//identity key
		//our public identity key
		if (!conversation.has_our_public_identity_key || (conversation.our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "our_public_identity_key is missing from the protobuf.");
		}
		this->storage->our_public_identity.set(conversation.our_public_identity_key.data, conversation.our_public_identity_key.len);
		//their public identity key
		if (!conversation.has_their_public_identity_key || (conversation.their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "their_public_identity is missing from the protobuf.");
		}
		this->storage->their_public_identity.set(conversation.their_public_identity_key.data, conversation.their_public_identity_key.len);

		//ephemeral keys
		//our private ephemeral key
		if (!conversation.has_our_private_ephemeral_key || (conversation.our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "our_private_ephemral is missing from the protobuf.");
		}
		this->storage->our_private_ephemeral.set(conversation.our_private_ephemeral_key.data, conversation.our_private_ephemeral_key.len);
		//our public ephemeral key
		if (!conversation.has_our_public_ephemeral_key || (conversation.our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "our_public_ephemeral is missing from the protobuf.");
		}
		this->storage->our_public_ephemeral.set(conversation.our_public_ephemeral_key.data, conversation.our_public_ephemeral_key.len);
		//their public ephemeral key
		if (!conversation.has_their_public_ephemeral_key || (conversation.their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception(PROTOBUF_MISSING_ERROR, "their_public_ephemeral is missing from the protobuf.");
		}
		this->storage->their_public_ephemeral.set(conversation.their_public_ephemeral_key.data, conversation.their_public_ephemeral_key.len);
		//their purported public ephemeral key
		if (conversation.has_their_purported_public_ephemeral && (conversation.their_purported_public_ephemeral.len == PUBLIC_KEY_SIZE)) {
			this->storage->their_purported_public_ephemeral.set(conversation.their_purported_public_ephemeral.data, conversation.their_purported_public_ephemeral.len);
		}

		//header and message keystores
		//skipped header and message keys
		this->skipped_header_and_message_keys = HeaderAndMessageKeyStore{
			conversation.skipped_header_and_message_keys,
			conversation.n_skipped_header_and_message_keys};
		//staged heeader and message keys
		this->staged_header_and_message_keys = HeaderAndMessageKeyStore{
			conversation.staged_header_and_message_keys,
			conversation.n_staged_header_and_message_keys};
	}

	std::ostream& Ratchet::print(std::ostream& stream) const {
		//root keys
		stream << "Root key:\n";
		this->storage->root_key.printHex(stream) << '\n';
		stream << "Purported root key:\n";
		this->storage->purported_root_key.printHex(stream) << '\n';

		//header keys
		stream << "Send header key:\n";
		this->storage->send_header_key.printHex(stream) << '\n';
		stream << "Receive header key:\n";
		this->storage->receive_header_key.printHex(stream) << '\n';
		stream << "Next send header key:\n";
		this->storage->next_send_header_key.printHex(stream) << '\n';
		stream << "Next receive header key:\n";
		this->storage->next_receive_header_key.printHex(stream) << '\n';
		stream << "Purported receive header key:\n";
		this->storage->purported_receive_header_key.printHex(stream) << '\n';
		stream << "Purported next receive header key:\n";
		this->storage->purported_next_receive_header_key.printHex(stream) << '\n';

		//chain keys
		stream << "Send chain key:\n";
		this->storage->send_chain_key.printHex(stream) << '\n';
		stream << "Receive chain key:\n";
		this->storage->receive_chain_key.printHex(stream) << '\n';
		stream << "Purported receive chain key:\n";
		this->storage->purported_receive_chain_key.printHex(stream) << '\n';

		//identity keys
		stream << "Our public identity key:\n";
		this->storage->our_public_identity.printHex(stream) << '\n';
		stream << "Their public identity key:\n";
		this->storage->their_public_identity.printHex(stream) << '\n';

		//ephemeral keys
		stream << "Our private ephemeral key:\n";
		this->storage->our_private_ephemeral.printHex(stream) << '\n';
		stream << "Our public ephemeral key:\n";
		this->storage->our_public_ephemeral.printHex(stream) << '\n';
		stream << "Their public ephemeral key:\n";
		this->storage->their_public_ephemeral.printHex(stream) << '\n';
		stream << "Their purported public ephemeral key:\n";
		this->storage->their_purported_public_ephemeral.printHex(stream) << '\n';

		//numbers
		stream << "Send message number: " << this->send_message_number << '\n';
		stream << "Receive message number: " << this->receive_message_number << '\n';
		stream << "Purported message number: " << this->purported_message_number << '\n';
		stream << "Previous message number: " << this->previous_message_number << '\n';
		stream << "Purported previous message number: " << this->purported_previous_message_number << '\n';

		//others
		stream << "Ratchet flag: " << this->ratchet_flag << '\n';
		stream << "Am I Alice: " << static_cast<bool>(this->role) << '\n';
		stream << "Received valid: " << this->received_valid << '\n';
		stream << "Header decryptability: " << static_cast<unsigned int>(this->header_decryptable) << '\n';

		//header and message keystores
		stream << "Skipped header and message keys:\n";
		this->skipped_header_and_message_keys.print(stream) << '\n';
		stream << "Staged header and message keys:\n";
		this->staged_header_and_message_keys.print(stream) << '\n';

		return stream;
	}
}
