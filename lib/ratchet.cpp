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
#include "exception.hpp"
#include "gsl.hpp"

namespace Molch {
	void Ratchet::init() {
		this->storage = std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>>(sodium_malloc<RatchetStorage>(1));
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
		Expects(!our_private_identity.empty
				&& !our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_private_ephemeral.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		this->init();

		//find out if we are alice by comparing both public keys
		//the one with the bigger public key is alice
		this->role = [&our_public_identity, &their_public_identity] () {
			if (our_public_identity > their_public_identity) {
				return Role::ALICE;
			} else if (our_public_identity < their_public_identity) {
				return Role::BOB;
			} else {
				throw Exception{status_type::SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!"};
			}
		}();

		//derive initial chain, root and header keys
		auto derived_keys{derive_initial_root_chain_and_header_keys(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			this->role)};
		auto& storage{this->storage};
		storage->root_key = derived_keys.root_key;
		if (derived_keys.send_chain_key.has_value()) {
			storage->send_chain_key = derived_keys.send_chain_key.value();
		} else {
			storage->send_chain_key.clearKey();
		}
		if (derived_keys.receive_chain_key.has_value()) {
			storage->receive_chain_key = derived_keys.receive_chain_key.value();
		} else {
			storage->receive_chain_key.clearKey();
		}
		storage->send_header_key = std::move(derived_keys.send_header_key);
		if (derived_keys.receive_header_key.has_value()) {
			storage->receive_header_key = derived_keys.receive_header_key.value();
		} else {
			storage->receive_header_key.clearKey();
		}
		storage->next_send_header_key = derived_keys.next_send_header_key;
		storage->next_receive_header_key = derived_keys.next_receive_header_key;

		//copy keys into state
		//our public identity
		storage->our_public_identity = our_public_identity;
		//their_public_identity
		storage->their_public_identity = their_public_identity;
		//our_private_ephemeral
		storage->our_private_ephemeral = our_private_ephemeral;
		//our_public_ephemeral
		storage->our_public_ephemeral = our_public_ephemeral;
		//their_public_ephemeral
		storage->their_public_ephemeral = their_public_ephemeral;

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
		auto& storage{this->storage};
		if (this->ratchet_flag) {
			//DHRs = generateECDH()
			TRY_VOID(crypto_box_keypair(
					storage->our_public_ephemeral,
					storage->our_private_ephemeral));
			storage->our_public_ephemeral.empty = false;
			storage->our_private_ephemeral.empty = false;

			//HKs = NHKs
			storage->send_header_key = storage->next_send_header_key;

			//clone the root key for it to not be overwritten in the next step
			RootKey root_key_backup{storage->root_key};

			//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
			auto derived_keys{derive_root_next_header_and_chain_keys(
				storage->our_private_ephemeral,
				storage->our_public_ephemeral,
				storage->their_public_ephemeral,
				root_key_backup,
				this->role)};
			storage->root_key = derived_keys.root_key;
			storage->next_send_header_key = derived_keys.next_header_key;
			storage->send_chain_key = derived_keys.chain_key;

			//PNs = Ns
			this->previous_message_number = this->send_message_number;

			//Ns = 0
			this->send_message_number = 0;

			//ratchet_flag = False
			this->ratchet_flag = false;
		}

		//MK = HMAC-HASH(CKs, "0")
		message_key = storage->send_chain_key.deriveMessageKey();

		//copy the other data to the output
		//(corresponds to
		//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
		//  in the axolotl specification)
		//HKs:
		send_header_key = storage->send_header_key.value();
		//Ns
		send_message_number = this->send_message_number;
		//PNs
		previous_send_message_number = this->previous_message_number;
		//DHRs
		our_public_ephemeral = storage->our_public_ephemeral;

		//Ns = Ns + 1
		this->send_message_number++;

		//clone the chain key for it to not be overwritten in the next step
		ChainKey chain_key_backup{storage->send_chain_key};

		//CKs = HMAC-HASH(CKs, "1")
		storage->send_chain_key = chain_key_backup.deriveChainKey();
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
		Expects((this->header_decryptable == HeaderDecryptability::NOT_TRIED)
				&& (header_decryptable != HeaderDecryptability::NOT_TRIED));

		this->header_decryptable = header_decryptable;
	}

	constexpr size_t maximum_skipped_messages{500};

	/*
	 * This corresponds to "stage_skipped_header_and_message_keys" from the
	 * axolotl protocol description.
	 *
	 * Calculates all the message keys up to the purported message number and
	 * saves the skipped ones in the ratchet's staging area.
	 */
	void Ratchet::stageSkippedHeaderAndMessageKeys(
			HeaderAndMessageKeyStore& staging_area,
			ChainKey * const output_chain_key, //output, optional
			MessageKey * const output_message_key, //output, optional
			const HeaderKey& current_header_key,
			const uint32_t current_message_number,
			const uint32_t future_message_number,
			const ChainKey& chain_key) {
		//when chain key is <none>, do nothing
		if (chain_key.isNone()) {
			return;
		}

		if (future_message_number > (current_message_number + maximum_skipped_messages)) {
			throw Exception{status_type::RECEIVE_ERROR, "Too many messagges in this message chain have been skipped."};
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
		this->skipped_header_and_message_keys.add(this->staged_header_and_message_keys);
		this->staged_header_and_message_keys.clear();
		this->skipped_header_and_message_keys.removeOutdatedAndTrimSize();
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
		Expects(!their_purported_public_ephemeral.empty);

		if (!this->received_valid) {
			//abort because the previously received message hasn't been verified yet.
			throw Exception{status_type::INVALID_STATE, "Previously received message hasn't been verified yet."};
		}

		//header decryption hasn't been tried yet
		if (this->header_decryptable == HeaderDecryptability::NOT_TRIED) {
			throw Exception{status_type::INVALID_STATE, "Header decryption hasn't been tried yet."};
		}

		auto& storage{this->storage};

		if (!storage->receive_header_key.isNone() && (this->header_decryptable == HeaderDecryptability::CURRENT_DECRYPTABLE)) { //still the same message chain
			//Np = read(): get the purported message number from the input
			this->purported_message_number = purported_message_number;

			//CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
			Ratchet::stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				&storage->purported_receive_chain_key,
				&message_key,
				storage->receive_header_key,
				this->receive_message_number,
				purported_message_number,
				storage->receive_chain_key);
		} else { //new message chain
			//if ratchet_flag or not Dec(NHKr, header)
			if (this->ratchet_flag || (this->header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				throw Exception{status_type::DECRYPT_ERROR, "Undecryptable."};
			}

			//Np = read(): get the purported message number from the input
			this->purported_message_number = purported_message_number;
			//PNp = read(): get the purported previous message number from the input
			this->purported_previous_message_number = purported_previous_message_number;
			//DHRp = read(): get the purported ephemeral from the input
			storage->their_purported_public_ephemeral = their_purported_public_ephemeral;

			//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
			Ratchet::stageSkippedHeaderAndMessageKeys(
					this->staged_header_and_message_keys,
					nullptr, //output_chain_key
					nullptr, //output_message_key
					storage->receive_header_key,
					this->receive_message_number,
					purported_previous_message_number,
					storage->receive_chain_key);

			//HKp = NHKr
			storage->purported_receive_header_key = storage->next_receive_header_key;

			//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
			auto derived_keys{derive_root_next_header_and_chain_keys(
					storage->our_private_ephemeral,
					storage->our_public_ephemeral,
					their_purported_public_ephemeral,
					storage->root_key,
					this->role)};
			storage->purported_root_key = derived_keys.root_key;
			storage->purported_next_receive_header_key = derived_keys.next_header_key;
			storage->purported_receive_chain_key = derived_keys.chain_key;

			//backup the purported chain key because it will get overwritten in the next step
			ChainKey purported_chain_key_backup{storage->purported_receive_chain_key};

			//CKp, MK = staged_header_and_message_keys(HKp, 0, Np, CKp)
			Ratchet::stageSkippedHeaderAndMessageKeys(
					this->staged_header_and_message_keys,
					&storage->purported_receive_chain_key,
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
			this->staged_header_and_message_keys.clear();
			return;
		}

		if (this->storage->receive_header_key.isNone() || (header_decryptable != HeaderDecryptability::CURRENT_DECRYPTABLE)) { //new message chain
			if (this->ratchet_flag || (header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				//if ratchet_flag or not Dec(NHKr, header)
				//clear purported message and header keys
				this->staged_header_and_message_keys.clear();
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
			this->storage->our_private_ephemeral.zero();
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

#define throw_if_missing(name) \
	if ((name).empty) {\
		throw Exception(status_type::EXPORT_ERROR, "Some ratchet data is missing or has an incorrect size.");\
	}

	ProtobufCConversation* Ratchet::exportProtobuf(Arena& arena) const {
		protobuf_arena_create(arena, ProtobufCConversation, conversation);

		const auto& storage{*this->storage};

		//root keys
		//root key
		const auto& root_key{storage.root_key};
		throw_if_missing(root_key);
		protobuf_optional_bytes_arena_export(arena, conversation, root_key, ROOT_KEY_SIZE);
		//purported root key
		const auto& purported_root_key{storage.purported_root_key};
		if (!purported_root_key.empty) {
			protobuf_optional_bytes_arena_export(arena, conversation, purported_root_key, ROOT_KEY_SIZE);
		}

		//header keys
		//send header key
		const auto& role = this->role;
		if (role == Role::BOB) {
			if (!storage.send_header_key.has_value()) {
				throw Exception{status_type::EXPORT_ERROR, "send_header_key missing or has an incorrect size."};
			}
			const auto& send_header_key{storage.send_header_key.value()};
			protobuf_optional_bytes_arena_export(arena, conversation, send_header_key, HEADER_KEY_SIZE);
		}
		//receive header key
		const auto& receive_header_key{storage.receive_header_key};
		if ((role == Role::ALICE) && receive_header_key.empty) {
			throw Exception{status_type::EXPORT_ERROR, "receive_header_key missing or has an incorrect size."};
		}
		protobuf_optional_bytes_arena_export(arena, conversation, receive_header_key, HEADER_KEY_SIZE);
		//next send header key
		const auto& next_send_header_key{storage.next_send_header_key};
		throw_if_missing(next_send_header_key);
		protobuf_optional_bytes_arena_export(arena, conversation, next_send_header_key, HEADER_KEY_SIZE);
		//next receive header key
		const auto& next_receive_header_key{storage.next_receive_header_key};
		throw_if_missing(next_receive_header_key);
		protobuf_optional_bytes_arena_export(arena, conversation, next_receive_header_key, HEADER_KEY_SIZE);
		//purported receive header key
		const auto& purported_receive_header_key{storage.purported_receive_header_key};
		if (!purported_receive_header_key.empty) {
			conversation->purported_receive_header_key.data = arena.allocate<unsigned char>(HEADER_KEY_SIZE);
			protobuf_optional_bytes_arena_export(arena, conversation, purported_receive_header_key, HEADER_KEY_SIZE);
		}
		//purported next receive header key
		const auto& purported_next_receive_header_key{storage.purported_next_receive_header_key};
		if (!purported_next_receive_header_key.empty) {
			protobuf_optional_bytes_arena_export(arena, conversation, purported_next_receive_header_key, HEADER_KEY_SIZE);
		}

		//chain keys
		//send chain key
		const auto& send_chain_key{storage.send_chain_key};
		if ((role == Role::BOB) && send_chain_key.empty) {
			throw Exception{status_type::EXPORT_ERROR, "send_chain_key missing or has an invalid size."};
		}
		protobuf_optional_bytes_arena_export(arena, conversation, send_chain_key, CHAIN_KEY_SIZE);
		//receive chain key
		const auto& receive_chain_key{storage.receive_chain_key};
		if ((role == Role::ALICE) && receive_chain_key.empty) {
			throw Exception{status_type::EXPORT_ERROR, "receive_chain_key missing or has an incorrect size."};
		}
		protobuf_optional_bytes_arena_export(arena, conversation, receive_chain_key, CHAIN_KEY_SIZE);
		//purported receive chain key
		const auto& purported_receive_chain_key{storage.purported_receive_chain_key};
		if (!purported_receive_chain_key.empty) {
			protobuf_optional_bytes_arena_export(arena, conversation, purported_receive_chain_key, CHAIN_KEY_SIZE);
		}

		//identity key
		//our public identity key
		const auto& our_public_identity_key{storage.our_public_identity};
		throw_if_missing(our_public_identity_key);
		protobuf_optional_bytes_arena_export(arena, conversation, our_public_identity_key, PUBLIC_KEY_SIZE);
		//their public identity key
		const auto& their_public_identity_key{storage.their_public_identity};
		throw_if_missing(their_public_identity_key);
		protobuf_optional_bytes_arena_export(arena, conversation, their_public_identity_key, PUBLIC_KEY_SIZE);

		//ephemeral keys
		//our private ephemeral key
		const auto& our_private_ephemeral_key{storage.our_private_ephemeral};
		throw_if_missing(our_private_ephemeral_key);
		protobuf_optional_bytes_arena_export(arena, conversation, our_private_ephemeral_key, PRIVATE_KEY_SIZE);
		//our public ephemeral key
		const auto& our_public_ephemeral_key{storage.our_public_ephemeral};
		throw_if_missing(our_public_ephemeral_key);
		protobuf_optional_bytes_arena_export(arena, conversation, our_public_ephemeral_key, PUBLIC_KEY_SIZE);
		//their public ephemeral key
		const auto& their_public_ephemeral_key{storage.their_public_ephemeral};
		throw_if_missing(their_public_ephemeral_key);
		protobuf_optional_bytes_arena_export(arena, conversation, their_public_ephemeral_key, PUBLIC_KEY_SIZE);
		//their purported public ephemeral key
		const auto& their_purported_public_ephemeral{storage.their_purported_public_ephemeral};
		if (!their_purported_public_ephemeral.empty) {
			protobuf_optional_bytes_arena_export(arena, conversation, their_purported_public_ephemeral, PUBLIC_KEY_SIZE);
		}

		//message numbers
		protobuf_optional_export(conversation, send_message_number, this->send_message_number);
		protobuf_optional_export(conversation, receive_message_number, this->receive_message_number);
		protobuf_optional_export(conversation, purported_message_number, this->purported_message_number);
		protobuf_optional_export(conversation, previous_message_number, this->previous_message_number);
		protobuf_optional_export(conversation, purported_previous_message_number, this->purported_previous_message_number);

		//flags
		protobuf_optional_export(conversation, ratchet_flag, this->ratchet_flag);
		protobuf_optional_export(conversation, am_i_alice, static_cast<bool>(role));
		protobuf_optional_export(conversation, received_valid, this->received_valid);

		//header decryptability
		const auto& header_decryptable{[&] () {
				switch (this->header_decryptable) {
					case HeaderDecryptability::CURRENT_DECRYPTABLE:
						return MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE;

					case HeaderDecryptability::NEXT_DECRYPTABLE:
						return MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE;

					case HeaderDecryptability::UNDECRYPTABLE:
						return MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE;

					case HeaderDecryptability::NOT_TRIED:
						return MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED;

					default:
						throw Exception{status_type::INVALID_VALUE, "Invalid value of ratchet->header_decryptable."};
			}
		}()};
		protobuf_optional_export(conversation, header_decryptable, header_decryptable);

		//keystores
		//skipped header and message keystore
		protobuf_array_arena_export(arena, conversation, skipped_header_and_message_keys, this->skipped_header_and_message_keys);
		//staged header and message keystore
		protobuf_array_arena_export(arena, conversation, staged_header_and_message_keys, this->staged_header_and_message_keys);

		return conversation;
	}

	Ratchet::Ratchet(const ProtobufCConversation& conversation) {
		this->init();

		//import all the stuff
		//message numbers
		//send message number
		if (!conversation.has_send_message_number) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct."};
		}
		this->send_message_number = conversation.send_message_number;
		//receive message number
		if (!conversation.has_receive_message_number) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct."};
		}
		this->receive_message_number = conversation.receive_message_number;
		//purported message number
		if (!conversation.has_purported_message_number) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct."};
		}
		this->purported_message_number = conversation.purported_message_number;
		//previous message number
		if (!conversation.has_previous_message_number) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct."};
		}
		this->previous_message_number = conversation.previous_message_number;
		//purported previous message number
		if (!conversation.has_purported_previous_message_number) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct."};
		}
		this->purported_previous_message_number = conversation.purported_previous_message_number;


		//flags
		//ratchet flag
		if (!conversation.has_ratchet_flag) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct."};
		}
		this->ratchet_flag = conversation.ratchet_flag;
		//am I Alice
		if (!conversation.has_am_i_alice) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct."};
		}
		this->role = static_cast<Role>(conversation.am_i_alice);
		//received valid
		if (!conversation.has_received_valid) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct."};
		}
		this->received_valid = conversation.received_valid;


		//header decryptable
		if (!conversation.has_header_decryptable) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct."};
		}
		this->header_decryptable = [&] () {
			switch (conversation.header_decryptable) {
				case MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__CURRENT_DECRYPTABLE:
					return HeaderDecryptability::CURRENT_DECRYPTABLE;

				case MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__NEXT_DECRYPTABLE:
					return HeaderDecryptability::NEXT_DECRYPTABLE;

				case MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__UNDECRYPTABLE:
					return HeaderDecryptability::UNDECRYPTABLE;

				case MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY__NOT_TRIED:
					return HeaderDecryptability::NOT_TRIED;

				case _MOLCH__PROTOBUF__CONVERSATION__HEADER_DECRYPTABILITY_IS_INT_SIZE:
				default:
					throw Exception{status_type::INVALID_VALUE, "header_decryptable has an invalid value."};
			}
		}();

		//root keys
		//root key
		if (!conversation.has_root_key || (conversation.root_key.len != ROOT_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "root_key is missing from protobuf."};
		}
		this->storage->root_key.set({
				uchar_to_byte(conversation.root_key.data),
				conversation.root_key.len});
		//purported root key
		if (conversation.has_purported_root_key && (conversation.purported_root_key.len == ROOT_KEY_SIZE)) {
			this->storage->purported_root_key.set({
					uchar_to_byte(conversation.purported_root_key.data),
					conversation.purported_root_key.len});
		}

		//header key
		//send header key
		if (!conversation.has_send_header_key || (conversation.send_header_key.len != HEADER_KEY_SIZE)) {
			if (this->role == Role::BOB) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "send_header_key is missing from the protobuf."};
			}
			this->storage->send_header_key.reset();
		} else {
			this->storage->send_header_key.emplace(span<std::byte>(
					uchar_to_byte(conversation.send_header_key.data),
					conversation.send_header_key.len));
		}
		//receive header key
		if ((this->role == Role::ALICE) &&
				(!conversation.has_receive_header_key || (conversation.receive_header_key.len != HEADER_KEY_SIZE))) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "receive_header_key is missing from protobuf."};
		}
		this->storage->receive_header_key.set({
				uchar_to_byte(conversation.receive_header_key.data),
				conversation.receive_header_key.len});
		//next send header key
		if (!conversation.has_next_send_header_key || (conversation.next_send_header_key.len != HEADER_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "next_send_header_key is missing from protobuf."};
		}
		this->storage->next_send_header_key.set({
				uchar_to_byte(conversation.next_send_header_key.data),
				conversation.next_send_header_key.len});
		//next receive header key
		if (!conversation.has_next_receive_header_key || (conversation.next_receive_header_key.len != HEADER_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "next_receive_header_key is missing from protobuf."};
		}
		this->storage->next_receive_header_key.set({
				uchar_to_byte(conversation.next_receive_header_key.data),
				conversation.next_receive_header_key.len});
		//purported receive header key
		if (conversation.has_purported_receive_header_key && (conversation.purported_receive_header_key.len == HEADER_KEY_SIZE)) {
			this->storage->purported_receive_header_key.set({
					uchar_to_byte(conversation.purported_receive_header_key.data),
					conversation.purported_receive_header_key.len});
		}
		//purported next receive header key
		if (conversation.has_purported_next_receive_header_key && (conversation.purported_next_receive_header_key.len == HEADER_KEY_SIZE)) {
			this->storage->purported_next_receive_header_key.set({
					uchar_to_byte(conversation.purported_next_receive_header_key.data),
					conversation.purported_next_receive_header_key.len});
		}

		//chain keys
		//send chain key
		if ((this->role == Role::BOB) &&
				(!conversation.has_send_chain_key || (conversation.send_chain_key.len != CHAIN_KEY_SIZE))) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "send_chain_key is missing from the potobuf."};
		}
		this->storage->send_chain_key.set({
				uchar_to_byte(conversation.send_chain_key.data),
				conversation.send_chain_key.len});
		//receive chain key
		if ((this->role == Role::ALICE) &&
				(!conversation.has_receive_chain_key || (conversation.receive_chain_key.len != CHAIN_KEY_SIZE))) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "receive_chain_key is missing from the protobuf."};
		}
		this->storage->receive_chain_key.set({
				uchar_to_byte(conversation.receive_chain_key.data),
				conversation.receive_chain_key.len});
		//purported receive chain key
		if (conversation.has_purported_receive_chain_key && (conversation.purported_receive_chain_key.len == CHAIN_KEY_SIZE)) {
			this->storage->purported_receive_chain_key.set({
					uchar_to_byte(conversation.purported_receive_chain_key.data),
					conversation.purported_receive_chain_key.len});
		}

		//identity key
		//our public identity key
		if (!conversation.has_our_public_identity_key || (conversation.our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "our_public_identity_key is missing from the protobuf."};
		}
		this->storage->our_public_identity.set({
				uchar_to_byte(conversation.our_public_identity_key.data),
				conversation.our_public_identity_key.len});
		//their public identity key
		if (!conversation.has_their_public_identity_key || (conversation.their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "their_public_identity is missing from the protobuf."};
		}
		this->storage->their_public_identity.set({
				uchar_to_byte(conversation.their_public_identity_key.data),
				conversation.their_public_identity_key.len});

		//ephemeral keys
		//our private ephemeral key
		if (!conversation.has_our_private_ephemeral_key || (conversation.our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "our_private_ephemral is missing from the protobuf."};
		}
		this->storage->our_private_ephemeral.set({
				uchar_to_byte(conversation.our_private_ephemeral_key.data),
				conversation.our_private_ephemeral_key.len});
		//our public ephemeral key
		if (!conversation.has_our_public_ephemeral_key || (conversation.our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "our_public_ephemeral is missing from the protobuf."};
		}
		this->storage->our_public_ephemeral.set({
				uchar_to_byte(conversation.our_public_ephemeral_key.data),
				conversation.our_public_ephemeral_key.len});
		//their public ephemeral key
		if (!conversation.has_their_public_ephemeral_key || (conversation.their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "their_public_ephemeral is missing from the protobuf."};
		}
		this->storage->their_public_ephemeral.set({
				uchar_to_byte(conversation.their_public_ephemeral_key.data),
				conversation.their_public_ephemeral_key.len});
		//their purported public ephemeral key
		if (conversation.has_their_purported_public_ephemeral && (conversation.their_purported_public_ephemeral.len == PUBLIC_KEY_SIZE)) {
			this->storage->their_purported_public_ephemeral.set({
					uchar_to_byte(conversation.their_purported_public_ephemeral.data),
					conversation.their_purported_public_ephemeral.len});
		}

		//header and message keystores
		//skipped header and message keys
		this->skipped_header_and_message_keys = HeaderAndMessageKeyStore{{
			conversation.skipped_header_and_message_keys,
			conversation.n_skipped_header_and_message_keys}};
		//staged heeader and message keys
		this->staged_header_and_message_keys = HeaderAndMessageKeyStore{{
			conversation.staged_header_and_message_keys,
			conversation.n_staged_header_and_message_keys}};
	}

	std::ostream& Ratchet::print(std::ostream& stream) const {
		const auto& storage{this->storage};
		//root keys
		stream << "Root key:\n";
		storage->root_key.printHex(stream) << '\n';
		stream << "Purported root key:\n";
		storage->purported_root_key.printHex(stream) << '\n';

		//header keys
		if (storage->send_header_key.has_value()) {
			stream << "Send header key:\n";
			storage->send_header_key.value().printHex(stream) << '\n';
		}
		stream << "Receive header key:\n";
		storage->receive_header_key.printHex(stream) << '\n';
		stream << "Next send header key:\n";
		storage->next_send_header_key.printHex(stream) << '\n';
		stream << "Next receive header key:\n";
		storage->next_receive_header_key.printHex(stream) << '\n';
		stream << "Purported receive header key:\n";
		storage->purported_receive_header_key.printHex(stream) << '\n';
		stream << "Purported next receive header key:\n";
		storage->purported_next_receive_header_key.printHex(stream) << '\n';

		//chain keys
		stream << "Send chain key:\n";
		storage->send_chain_key.printHex(stream) << '\n';
		stream << "Receive chain key:\n";
		storage->receive_chain_key.printHex(stream) << '\n';
		stream << "Purported receive chain key:\n";
		storage->purported_receive_chain_key.printHex(stream) << '\n';

		//identity keys
		stream << "Our public identity key:\n";
		storage->our_public_identity.printHex(stream) << '\n';
		stream << "Their public identity key:\n";
		storage->their_public_identity.printHex(stream) << '\n';

		//ephemeral keys
		stream << "Our private ephemeral key:\n";
		storage->our_private_ephemeral.printHex(stream) << '\n';
		stream << "Our public ephemeral key:\n";
		storage->our_public_ephemeral.printHex(stream) << '\n';
		stream << "Their public ephemeral key:\n";
		storage->their_public_ephemeral.printHex(stream) << '\n';
		stream << "Their purported public ephemeral key:\n";
		storage->their_purported_public_ephemeral.printHex(stream) << '\n';

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
