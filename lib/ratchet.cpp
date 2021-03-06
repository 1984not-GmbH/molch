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

#include "molch/constants.h"
#include "ratchet.hpp"
#include "key-derivation.hpp"
#include "gsl.hpp"

namespace Molch {
	void Ratchet::init() {
		this->storage = std::unique_ptr<RatchetStorage,SodiumDeleter<RatchetStorage>>(sodium_malloc<RatchetStorage>(1));
		new (this->storage.get()) RatchetStorage{};
	}

	Ratchet::Ratchet() {
		this->init();
	}

	result<Ratchet> Ratchet::create(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral) {
		Ratchet ratchet;

		//find out if we are alice by comparing both public keys
		//the one with the bigger public key is alice
		OUTCOME_TRY(role, [&our_public_identity, &their_public_identity] () -> result<Role> {
			if (our_public_identity > their_public_identity) {
				return Role::ALICE;
			} else if (our_public_identity < their_public_identity) {
				return Role::BOB;
			} else {
				return Error(status_type::SHOULDNT_HAPPEN, "This mustn't happen, both conversation partners have the same public key!");
			}
		}());
		ratchet.role = role;

		//derive initial chain, root and header keys
		OUTCOME_TRY(derived_keys, derive_initial_root_chain_and_header_keys(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			ratchet.role));
		auto& storage{ratchet.storage};
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
		ratchet.ratchet_flag = static_cast<bool>(ratchet.role);
		ratchet.received_valid = true; //allowing the receival of new messages
		ratchet.header_decryptable = HeaderDecryptability::NOT_TRIED;
		ratchet.send_message_number = 0;
		ratchet.receive_message_number = 0;
		ratchet.previous_message_number = 0;

		return ratchet;
	}

	result<Ratchet::SendData> Ratchet::getSendData() {
		auto& storage{this->storage};
		SendData data;
		if (this->ratchet_flag) {
			//DHRs = generateECDH()
			OUTCOME_TRY(crypto_box_keypair(
					storage->our_public_ephemeral,
					storage->our_private_ephemeral));

			//HKs = NHKs
			storage->send_header_key = storage->next_send_header_key;

			//clone the root key for it to not be overwritten in the next step
			EmptyableRootKey root_key_backup{storage->root_key};

			//RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRs, DHRr)))
			OUTCOME_TRY(derived_keys, derive_root_next_header_and_chain_keys(
				storage->our_private_ephemeral,
				storage->our_public_ephemeral,
				storage->their_public_ephemeral,
				root_key_backup,
				this->role));
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
		OUTCOME_TRY(message_key, storage->send_chain_key.deriveMessageKey());
		data.message_key = message_key;

		//copy the other data to the output
		//(corresponds to
		//  msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
		//  in the axolotl specification)
		//HKs:
		if (not storage->send_header_key.has_value()) {
			return {status_type::INVALID_STATE, "Send header key is missing."};
		}
		data.header_key = storage->send_header_key.value();
		//Ns
		data.message_number = this->send_message_number;
		//PNs
		data.previous_message_number = this->previous_message_number;
		//DHRs
		data.ephemeral = storage->our_public_ephemeral;

		//Ns = Ns + 1
		this->send_message_number++;

		//CKs = HMAC-HASH(CKs, "1")
		OUTCOME_TRY(send_chain_key, storage->send_chain_key.deriveChainKey());
		storage->send_chain_key = send_chain_key;

		return data;
	}

	Ratchet::ReceiveHeaderKeys Ratchet::getReceiveHeaderKeys() const noexcept {
		ReceiveHeaderKeys header_keys;
		header_keys.current = this->storage->receive_header_key;
		header_keys.next = this->storage->next_receive_header_key;

		return header_keys;
	}

	result<void> Ratchet::setHeaderDecryptability(const HeaderDecryptability header_decryptable) noexcept {
		FulfillOrFail((this->header_decryptable == HeaderDecryptability::NOT_TRIED)
				&& (header_decryptable != HeaderDecryptability::NOT_TRIED));

		this->header_decryptable = header_decryptable;

		return outcome::success();
	}

	constexpr size_t maximum_skipped_messages{500};

	/*
	 * This corresponds to "stage_skipped_header_and_message_keys" from the
	 * axolotl protocol description.
	 *
	 * Calculates all the message keys up to the purported message number and
	 * saves the skipped ones in the ratchet's staging area.
	 */
	static result<void> stageSkippedHeaderAndMessageKeys(
			HeaderAndMessageKeyStore& staging_area,
			EmptyableChainKey * const output_chain_key, //output, optional
			MessageKey * const output_message_key, //output, optional
			const EmptyableHeaderKey& current_header_key,
			const uint32_t current_message_number,
			const uint32_t future_message_number,
			const EmptyableChainKey& chain_key) {
		//when chain key is <none>, do nothing
		if (chain_key.isNone()) {
			return outcome::success();
		}

		if (future_message_number > (current_message_number + maximum_skipped_messages)) {
			return Error(status_type::RECEIVE_ERROR, "Too many messagges in this message chain have been skipped.");
		}

		//set current_chain_key to chain key to initialize it for the calculation that's
		//following
		EmptyableChainKey current_chain_key{chain_key};

		for (uint32_t pos{current_message_number}; pos < future_message_number; pos++) {
			OUTCOME_TRY(current_message_key, current_chain_key.deriveMessageKey());
			staging_area.add(current_header_key, current_message_key);
			OUTCOME_TRY(next_chain_key, current_chain_key.deriveChainKey());

			//shift chain keys
			current_chain_key = next_chain_key;
		}

		//derive the message key that will be returned
		if (output_message_key != nullptr) {
			OUTCOME_TRY(output_message_key_result, current_chain_key.deriveMessageKey());
			*output_message_key = output_message_key_result;
		}

		//derive the chain key that will be returned
		if (output_chain_key != nullptr) {
			OUTCOME_TRY(output_chain_key_result, current_chain_key.deriveChainKey());
			*output_chain_key = output_chain_key_result;
		}

		return outcome::success();
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

	result<MessageKey> Ratchet::receive(
			const PublicKey& their_purported_public_ephemeral,
			const uint32_t purported_message_number,
			const uint32_t purported_previous_message_number) {
		if (!this->received_valid) {
			//abort because the previously received message hasn't been verified yet.
			return Error(status_type::INVALID_STATE, "Previously received message hasn't been verified yet.");
		}

		//header decryption hasn't been tried yet
		if (this->header_decryptable == HeaderDecryptability::NOT_TRIED) {
			return Error(status_type::INVALID_STATE, "Header decryption hasn't been tried yet.");
		}

		auto& storage{this->storage};

		MessageKey message_key;
		if (!storage->receive_header_key.isNone() && (this->header_decryptable == HeaderDecryptability::CURRENT_DECRYPTABLE)) { //still the same message chain
			//Np = read(): get the purported message number from the input
			this->purported_message_number = purported_message_number;

			//CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
			OUTCOME_TRY(stageSkippedHeaderAndMessageKeys(
				this->staged_header_and_message_keys,
				&storage->purported_receive_chain_key,
				&message_key,
				storage->receive_header_key,
				this->receive_message_number,
				purported_message_number,
				storage->receive_chain_key));
		} else { //new message chain
			//if ratchet_flag or not Dec(NHKr, header)
			if (this->ratchet_flag || (this->header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				return Error(status_type::DECRYPT_ERROR, "Undecryptable.");
			}

			//Np = read(): get the purported message number from the input
			this->purported_message_number = purported_message_number;
			//PNp = read(): get the purported previous message number from the input
			this->purported_previous_message_number = purported_previous_message_number;
			//DHRp = read(): get the purported ephemeral from the input
			storage->their_purported_public_ephemeral = their_purported_public_ephemeral;

			//stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
			OUTCOME_TRY(stageSkippedHeaderAndMessageKeys(
					this->staged_header_and_message_keys,
					nullptr, //output_chain_key
					nullptr, //output_message_key
					storage->receive_header_key,
					this->receive_message_number,
					purported_previous_message_number,
					storage->receive_chain_key));

			//HKp = NHKr
			storage->purported_receive_header_key = storage->next_receive_header_key;

			//RKp, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
			OUTCOME_TRY(derived_keys, derive_root_next_header_and_chain_keys(
					storage->our_private_ephemeral,
					storage->our_public_ephemeral,
					their_purported_public_ephemeral,
					storage->root_key,
					this->role));
			storage->purported_root_key = derived_keys.root_key;
			storage->purported_next_receive_header_key = derived_keys.next_header_key;
			storage->purported_receive_chain_key = derived_keys.chain_key;

			//backup the purported chain key because it will get overwritten in the next step
			EmptyableChainKey purported_chain_key_backup{storage->purported_receive_chain_key};

			//CKp, MK = staged_header_and_message_keys(HKp, 0, Np, CKp)
			OUTCOME_TRY(stageSkippedHeaderAndMessageKeys(
					this->staged_header_and_message_keys,
					&storage->purported_receive_chain_key,
					&message_key,
					this->storage->purported_receive_header_key,
					0,
					purported_message_number,
					purported_chain_key_backup));
		}

		this->received_valid = false; //waiting for validation (feedback, if the message could actually be decrypted)

		return message_key;
	}

	/*
	 * Call this function after trying to decrypt a message and pass it if
	 * the decryption was successful or if it wasn't.
	 */
	result<void> Ratchet::setLastMessageAuthenticity(bool valid) noexcept {
		//prepare for being able to receive new messages
		this->received_valid = true;

		//backup header decryptability
		auto header_decryptable{this->header_decryptable};
		this->header_decryptable = HeaderDecryptability::NOT_TRIED;

		if (!valid) { //message couldn't be decrypted
			this->staged_header_and_message_keys.clear();
			return outcome::success();
		}

		if (this->storage->receive_header_key.isNone() || (header_decryptable != HeaderDecryptability::CURRENT_DECRYPTABLE)) { //new message chain
			if (this->ratchet_flag || (header_decryptable != HeaderDecryptability::NEXT_DECRYPTABLE)) {
				//if ratchet_flag or not Dec(NHKr, header)
				//clear purported message and header keys
				this->staged_header_and_message_keys.clear();
				return outcome::success();
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
			if (not this->storage->their_purported_public_ephemeral.has_value()) {
				return Error(status_type::INVALID_VALUE, "Their purported public ephemeral key is missing.");
			}
			this->storage->their_public_ephemeral = this->storage->their_purported_public_ephemeral.value();
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
		return outcome::success();
	}

#define error_if_missing(name) \
	if ((name).empty) {\
		return Error(status_type::EXPORT_ERROR, "Missing ");\
	}

	result<ProtobufCConversation*> Ratchet::exportProtobuf(Arena& arena) const {
		protobuf_arena_create(arena, ProtobufCConversation, conversation);

		const auto& storage{*this->storage};

		//root keys
		//root key
		const auto& root_key{storage.root_key};
		error_if_missing(root_key);
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, root_key, ROOT_KEY_SIZE);
		//purported root key
		const auto& purported_root_key{storage.purported_root_key};
		if (!purported_root_key.empty) {
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, purported_root_key, ROOT_KEY_SIZE);
		}

		//header keys
		//send header key
		const auto& role = this->role;
		if (not storage.send_header_key.has_value()) {
			if (role == Role::BOB) {
				return Error(status_type::EXPORT_ERROR, "send_header_key missing or has an incorrect size.");
			}
		} else {
			const auto& send_header_key{storage.send_header_key.value()};
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, send_header_key, HEADER_KEY_SIZE);
		}

		//receive header key
		const auto& receive_header_key{storage.receive_header_key};
		if ((role == Role::ALICE) && receive_header_key.empty) {
			return Error(status_type::EXPORT_ERROR, "receive_header_key missing or has an incorrect size.");
		}
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, receive_header_key, HEADER_KEY_SIZE);
		//next send header key
		const auto& next_send_header_key{storage.next_send_header_key};
		error_if_missing(next_send_header_key);
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, next_send_header_key, HEADER_KEY_SIZE);
		//next receive header key
		const auto& next_receive_header_key{storage.next_receive_header_key};
		error_if_missing(next_receive_header_key);
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, next_receive_header_key, HEADER_KEY_SIZE);
		//purported receive header key
		const auto& purported_receive_header_key{storage.purported_receive_header_key};
		if (!purported_receive_header_key.empty) {
			conversation->purported_receive_header_key.data = arena.allocate<unsigned char>(HEADER_KEY_SIZE);
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, purported_receive_header_key, HEADER_KEY_SIZE);
		}
		//purported next receive header key
		const auto& purported_next_receive_header_key{storage.purported_next_receive_header_key};
		if (!purported_next_receive_header_key.empty) {
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, purported_next_receive_header_key, HEADER_KEY_SIZE);
		}

		//chain keys
		//send chain key
		const auto& send_chain_key{storage.send_chain_key};
		if ((role == Role::BOB) && send_chain_key.empty) {
			return Error(status_type::EXPORT_ERROR, "send_chain_key missing or has an invalid size.");
		}
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, send_chain_key, CHAIN_KEY_SIZE);
		//receive chain key
		const auto& receive_chain_key{storage.receive_chain_key};
		if ((role == Role::ALICE) && receive_chain_key.empty) {
			return Error(status_type::EXPORT_ERROR, "receive_chain_key missing or has an incorrect size.");
		}
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, receive_chain_key, CHAIN_KEY_SIZE);
		//purported receive chain key
		const auto& purported_receive_chain_key{storage.purported_receive_chain_key};
		if (!purported_receive_chain_key.empty) {
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, purported_receive_chain_key, CHAIN_KEY_SIZE);
		}

		//identity key
		//our public identity key
		const auto& our_public_identity_key{storage.our_public_identity};
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, our_public_identity_key, PUBLIC_KEY_SIZE);
		//their public identity key
		const auto& their_public_identity_key{storage.their_public_identity};
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, their_public_identity_key, PUBLIC_KEY_SIZE);

		//ephemeral keys
		//our private ephemeral key
		const auto& our_private_ephemeral_key{storage.our_private_ephemeral};
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, our_private_ephemeral_key, PRIVATE_KEY_SIZE);
		//our public ephemeral key
		const auto& our_public_ephemeral_key{storage.our_public_ephemeral};
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, our_public_ephemeral_key, PUBLIC_KEY_SIZE);
		//their public ephemeral key
		const auto& their_public_ephemeral_key{storage.their_public_ephemeral};
		outcome_protobuf_optional_bytes_arena_export(arena, conversation, their_public_ephemeral_key, PUBLIC_KEY_SIZE);
		//their purported public ephemeral key
		const auto& their_purported_public_ephemeral_optional{storage.their_purported_public_ephemeral};
		if (their_purported_public_ephemeral_optional.has_value()) {
			const auto& their_purported_public_ephemeral{their_purported_public_ephemeral_optional.value()};
			outcome_protobuf_optional_bytes_arena_export(arena, conversation, their_purported_public_ephemeral, PUBLIC_KEY_SIZE);
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
		OUTCOME_TRY(header_decryptable, [&] () -> result<Molch__Protobuf__Conversation__HeaderDecryptability> {
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
						return Error(status_type::INVALID_VALUE, "Invalid value of ratchet->header_decryptable.");
			}
		}());
		protobuf_optional_export(conversation, header_decryptable, header_decryptable);

		//keystores
		//skipped header and message keystore
		outcome_protobuf_array_arena_export(arena, conversation, skipped_header_and_message_keys, this->skipped_header_and_message_keys);
		//staged header and message keystore
		outcome_protobuf_array_arena_export(arena, conversation, staged_header_and_message_keys, this->staged_header_and_message_keys);

		return conversation;
	}

	result<Ratchet> Ratchet::import(const ProtobufCConversation& conversation) {
		Ratchet ratchet;

		//import all the stuff
		//message numbers
		//send message number
		if (!conversation.has_send_message_number) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No send message number in Protobuf-C struct.");
		}
		ratchet.send_message_number = conversation.send_message_number;
		//receive message number
		if (!conversation.has_receive_message_number) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No receive message number in Protobuf-C struct.");
		}
		ratchet.receive_message_number = conversation.receive_message_number;
		//purported message number
		if (!conversation.has_purported_message_number) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No purported message number in Protobuf-C struct.");
		}
		ratchet.purported_message_number = conversation.purported_message_number;
		//previous message number
		if (!conversation.has_previous_message_number) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No previous message number in Protobuf-C struct.");
		}
		ratchet.previous_message_number = conversation.previous_message_number;
		//purported previous message number
		if (!conversation.has_purported_previous_message_number) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No purported previous message number in Protobuf-C struct.");
		}
		ratchet.purported_previous_message_number = conversation.purported_previous_message_number;


		//flags
		//ratchet flag
		if (!conversation.has_ratchet_flag) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No ratchet flag in Protobuf-C struct.");
		}
		ratchet.ratchet_flag = conversation.ratchet_flag;
		//am I Alice
		if (!conversation.has_am_i_alice) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No am I Alice flag in Protobuf-C struct.");
		}
		ratchet.role = static_cast<Role>(conversation.am_i_alice);
		//received valid
		if (!conversation.has_received_valid) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No received valid flag in Protobuf-C struct.");
		}
		ratchet.received_valid = conversation.received_valid;


		//header decryptable
		if (!conversation.has_header_decryptable) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "No header decryptable enum in Protobuf-C struct.");
		}
		OUTCOME_TRY(header_decryptability, [&] () -> result<HeaderDecryptability> {
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
					return Error(status_type::INVALID_VALUE, "header_decryptable has an invalid value.");
			}
		}());
		ratchet.header_decryptable = header_decryptability;

		//root keys
		//root key
		if (!conversation.has_root_key || (conversation.root_key.len != ROOT_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "root_key is missing from protobuf.");
		}
		OUTCOME_TRY(root_key, EmptyableRootKey::fromSpan({conversation.root_key}));
		ratchet.storage->root_key = root_key;
		//purported root key
		if (conversation.has_purported_root_key && (conversation.purported_root_key.len == ROOT_KEY_SIZE)) {
			OUTCOME_TRY(purported_root_key, EmptyableRootKey::fromSpan({conversation.purported_root_key}));
			ratchet.storage->purported_root_key = purported_root_key;
		}

		//header key
		//send header key
		if (!conversation.has_send_header_key || (conversation.send_header_key.len != HEADER_KEY_SIZE)) {
			if (ratchet.role == Role::BOB) {
				return Error(status_type::PROTOBUF_MISSING_ERROR, "send_header_key is missing from the protobuf.");
			}
			ratchet.storage->send_header_key.reset();
		} else {
		    OUTCOME_TRY(send_header_key, EmptyableHeaderKey::fromSpan({uchar_to_byte(conversation.send_header_key.data), conversation.send_header_key.len}));
			ratchet.storage->send_header_key.emplace(send_header_key);
		}
		//receive header key
		if ((ratchet.role == Role::ALICE) &&
				(!conversation.has_receive_header_key || (conversation.receive_header_key.len != HEADER_KEY_SIZE))) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "receive_header_key is missing from protobuf.");
		}
		OUTCOME_TRY(receive_header_key, EmptyableHeaderKey::fromSpan({conversation.receive_header_key}));
		ratchet.storage->receive_header_key = receive_header_key;
		//next send header key
		if (!conversation.has_next_send_header_key || (conversation.next_send_header_key.len != HEADER_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "next_send_header_key is missing from protobuf.");
		}
		OUTCOME_TRY(next_send_header_key, EmptyableHeaderKey::fromSpan({conversation.next_send_header_key}));
		ratchet.storage->next_send_header_key = next_send_header_key;
		//next receive header key
		if (!conversation.has_next_receive_header_key || (conversation.next_receive_header_key.len != HEADER_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "next_receive_header_key is missing from protobuf.");
		}
		OUTCOME_TRY(next_receive_header_key, EmptyableHeaderKey::fromSpan({conversation.next_receive_header_key}));
		ratchet.storage->next_receive_header_key = next_receive_header_key;
		//purported receive header key
		if (conversation.has_purported_receive_header_key && (conversation.purported_receive_header_key.len == HEADER_KEY_SIZE)) {
			OUTCOME_TRY(purported_receive_header_key, EmptyableHeaderKey::fromSpan({conversation.purported_receive_header_key}));
			ratchet.storage->purported_receive_header_key = purported_receive_header_key;
		}
		//purported next receive header key
		if (conversation.has_purported_next_receive_header_key && (conversation.purported_next_receive_header_key.len == HEADER_KEY_SIZE)) {
			OUTCOME_TRY(purported_next_receive_header_key, EmptyableHeaderKey::fromSpan({conversation.purported_next_receive_header_key}));
			ratchet.storage->purported_next_receive_header_key = purported_next_receive_header_key;
		}

		//chain keys
		//send chain key
		if ((ratchet.role == Role::BOB) &&
				(!conversation.has_send_chain_key || (conversation.send_chain_key.len != CHAIN_KEY_SIZE))) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "send_chain_key is missing from the potobuf.");
		}
		OUTCOME_TRY(send_chain_key, EmptyableChainKey::fromSpan({conversation.send_chain_key}));
		ratchet.storage->send_chain_key = send_chain_key;
		//receive chain key
		if ((ratchet.role == Role::ALICE) &&
				(!conversation.has_receive_chain_key || (conversation.receive_chain_key.len != CHAIN_KEY_SIZE))) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "receive_chain_key is missing from the protobuf.");
		}
		OUTCOME_TRY(receive_chain_key, EmptyableChainKey::fromSpan({conversation.receive_chain_key}));
		ratchet.storage->receive_chain_key = receive_chain_key;
		//purported receive chain key
		if (conversation.has_purported_receive_chain_key && (conversation.purported_receive_chain_key.len == CHAIN_KEY_SIZE)) {
			OUTCOME_TRY(purported_receive_chain_key, EmptyableChainKey::fromSpan({conversation.purported_receive_chain_key}));
			ratchet.storage->purported_receive_chain_key = purported_receive_chain_key;
		}

		//identity key
		//our public identity key
		if (!conversation.has_our_public_identity_key || (conversation.our_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "our_public_identity_key is missing from the protobuf.");
		}
		OUTCOME_TRY(our_public_identity, PublicKey::fromSpan({conversation.our_public_identity_key}));
		ratchet.storage->our_public_identity = our_public_identity;
		//their public identity key
		if (!conversation.has_their_public_identity_key || (conversation.their_public_identity_key.len != PUBLIC_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "their_public_identity is missing from the protobuf.");
		}
		OUTCOME_TRY(their_public_identity, PublicKey::fromSpan({conversation.their_public_identity_key}));
		ratchet.storage->their_public_identity = their_public_identity;

		//ephemeral keys
		//our private ephemeral key
		if (!conversation.has_our_private_ephemeral_key || (conversation.our_private_ephemeral_key.len != PRIVATE_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "our_private_ephemral is missing from the protobuf.");
		}
		OUTCOME_TRY(our_private_ephemeral, PrivateKey::fromSpan({conversation.our_private_ephemeral_key}));
		ratchet.storage->our_private_ephemeral = our_private_ephemeral;
		//our public ephemeral key
		if (!conversation.has_our_public_ephemeral_key || (conversation.our_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "our_public_ephemeral is missing from the protobuf.");
		}
		OUTCOME_TRY(our_public_ephemeral, PublicKey::fromSpan({conversation.our_public_ephemeral_key}));
		ratchet.storage->our_public_ephemeral = our_public_ephemeral;
		//their public ephemeral key
		if (!conversation.has_their_public_ephemeral_key || (conversation.their_public_ephemeral_key.len != PUBLIC_KEY_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "their_public_ephemeral is missing from the protobuf.");
		}
		OUTCOME_TRY(their_public_ephemeral, PublicKey::fromSpan({conversation.their_public_ephemeral_key}));
		ratchet.storage->their_public_ephemeral = their_public_ephemeral;
		//their purported public ephemeral key
		if (conversation.has_their_purported_public_ephemeral && (conversation.their_purported_public_ephemeral.len == PUBLIC_KEY_SIZE)) {
			OUTCOME_TRY(their_purported_public_ephemeral, PublicKey::fromSpan({conversation.their_purported_public_ephemeral}));
			ratchet.storage->their_purported_public_ephemeral = their_purported_public_ephemeral;
		}

		//header and message keystores
		//skipped header and message keys
		OUTCOME_TRY(skipped_header_and_message_keys, HeaderAndMessageKeyStore::import({
			conversation.skipped_header_and_message_keys,
			conversation.n_skipped_header_and_message_keys}));
		ratchet.skipped_header_and_message_keys = skipped_header_and_message_keys;
		//staged heeader and message keys
		OUTCOME_TRY(staged_header_and_message_keys, HeaderAndMessageKeyStore::import({
				conversation.staged_header_and_message_keys,
				conversation.n_staged_header_and_message_keys}));
		ratchet.staged_header_and_message_keys = staged_header_and_message_keys;

		return ratchet;
	}

	std::ostream& Ratchet::print(std::ostream& stream) const {
		const auto& storage{this->storage};
		//root keys
		stream << "Root key:\n";
		stream << storage->root_key << '\n';
		stream << "Purported root key:\n";
		stream << storage->purported_root_key << '\n';

		//header keys
		if (storage->send_header_key.has_value()) {
			stream << "Send header key:\n";
			stream << storage->send_header_key.value() << '\n';
		}
		stream << "Receive header key:\n";
		stream << storage->receive_header_key << '\n';
		stream << "Next send header key:\n";
		stream << storage->next_send_header_key << '\n';
		stream << "Next receive header key:\n";
		stream << storage->next_receive_header_key << '\n';
		stream << "Purported receive header key:\n";
		stream << storage->purported_receive_header_key << '\n';
		stream << "Purported next receive header key:\n";
		stream << storage->purported_next_receive_header_key << '\n';

		//chain keys
		stream << "Send chain key:\n";
		stream << storage->send_chain_key << '\n';
		stream << "Receive chain key:\n";
		stream << storage->receive_chain_key << '\n';
		stream << "Purported receive chain key:\n";
		stream << storage->purported_receive_chain_key << '\n';

		//identity keys
		stream << "Our public identity key:\n";
		stream << storage->our_public_identity << '\n';
		stream << "Their public identity key:\n";
		stream << storage->their_public_identity << '\n';

		//ephemeral keys
		stream << "Our private ephemeral key:\n";
		stream << storage->our_private_ephemeral << '\n';
		stream << "Our public ephemeral key:\n";
		stream << storage->our_public_ephemeral << '\n';
		stream << "Their public ephemeral key:\n";
		stream << storage->their_public_ephemeral << '\n';
		stream << "Their purported public ephemeral key:\n";
		if (storage->their_purported_public_ephemeral.has_value()) {
			stream << storage->their_purported_public_ephemeral.value() << '\n';
		} else {
			stream << "(empty)\n";
		}

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
		stream << this->skipped_header_and_message_keys << '\n';
		stream << "Staged header and message keys:\n";
		stream << this->staged_header_and_message_keys << '\n';

		return stream;
	}
}
