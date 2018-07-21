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

#include <exception>
#include <iterator>

#include "constants.h"
#include "conversation.hpp"
#include "packet.hpp"
#include "header.hpp"
#include "destroyers.hpp"
#include "gsl.hpp"

namespace Molch {
	Conversation& Conversation::move(Conversation&& conversation) noexcept {
		this->id_storage = conversation.id_storage;
		this->ratchet = std::move(conversation.ratchet);

		return *this;
	}

	Conversation::Conversation(Conversation&& conversation) noexcept {
		this->move(std::move(conversation));
	}

	Conversation& Conversation::operator=(Conversation&& conversation) noexcept {
		this->move(std::move(conversation));
		return *this;
	}

	/*
	 * Create a new conversation.
	 */
	void Conversation::create(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral) {
		Expects(!our_private_identity.empty
				&& !our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_public_ephemeral.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		//create random id
		this->id_storage.fillRandom();

		this->ratchet = Ratchet(
				our_private_identity,
				our_public_identity,
				their_public_identity,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_ephemeral);
	}

	Conversation::Conversation(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral) {
		this->create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	}

	/*
	 * Start a new conversation where we are the sender.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	Conversation::Conversation(
			const span<const std::byte> message, //message we want to send to the receiver
			Buffer& packet, //output
			const PublicKey& sender_public_identity, //who is sending this message?
			const PrivateKey& sender_private_identity,
			const PublicKey& receiver_public_identity,
			const span<const std::byte> receiver_prekey_list) { //PREKEY_AMOUNT * PUBLIC_KEY_SIZE
		Expects(!receiver_public_identity.empty
				&& !sender_public_identity.empty
				&& !sender_private_identity.empty
				&& (receiver_prekey_list.size() == (PREKEY_AMOUNT * PUBLIC_KEY_SIZE)));

		//create an ephemeral keypair
		PublicKey sender_public_ephemeral;
		PrivateKey sender_private_ephemeral;
		TRY_VOID(crypto_box_keypair(sender_public_ephemeral, sender_private_ephemeral));
		sender_public_ephemeral.empty = false;
		sender_private_ephemeral.empty = false;

		//choose a prekey
		auto prekey_number{randombytes_uniform(PREKEY_AMOUNT)};
		PublicKey receiver_public_prekey;
		receiver_public_prekey.set({
				&receiver_prekey_list[gsl::narrow_cast<ptrdiff_t>(prekey_number * PUBLIC_KEY_SIZE)],
				PUBLIC_KEY_SIZE});

		//initialize the conversation
		this->create(
				sender_private_identity,
				sender_public_identity,
				receiver_public_identity,
				sender_private_ephemeral,
				sender_public_ephemeral,
				receiver_public_prekey);

		packet = this->send(
				message,
				&sender_public_identity,
				&sender_public_ephemeral,
				&receiver_public_prekey);
	}

	/*
	 * Start a new conversation where we are the receiver.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	Conversation::Conversation(
			const span<const std::byte> packet, //received packet
			Buffer& message, //output
			const PublicKey& receiver_public_identity,
			const PrivateKey& receiver_private_identity,
			PrekeyStore& receiver_prekeys) { //prekeys of the receiver
		Expects(!receiver_public_identity.empty
				&& !receiver_private_identity.empty);

		uint32_t receive_message_number{0};
		uint32_t previous_receive_message_number{0};

		//get the senders keys and our public prekey from the packet
		TRY_WITH_RESULT(unverified_metadata_result, packet_get_metadata_without_verification(packet));
		const auto& unverified_metadata{unverified_metadata_result.value()};

		if (unverified_metadata.packet_type != molch_message_type::PREKEY_MESSAGE) {
			throw Exception{status_type::INVALID_VALUE, "Packet is not a prekey message."};
		}
		if (not unverified_metadata.prekey_metadata.has_value()) {
			throw Exception(status_type::INVALID_VALUE, "Prekey Metadata is missing.");
		}
		const auto& unverified_prekey_metadata{unverified_metadata.prekey_metadata.value()};

		//get the private prekey that corresponds to the public prekey used in the message
		PrivateKey receiver_private_prekey;
		receiver_prekeys.getPrekey(unverified_prekey_metadata.prekey, receiver_private_prekey);

		this->create(
				receiver_private_identity,
				receiver_public_identity,
				unverified_prekey_metadata.identity,
				receiver_private_prekey,
				unverified_prekey_metadata.prekey,
				unverified_prekey_metadata.ephemeral);

		message = this->receive(
				packet,
				receive_message_number,
				previous_receive_message_number);
	}

	/*
	 * Send a message using an existing conversation.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	Buffer Conversation::send(
			const span<const std::byte> message,
			const PublicKey * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
			const PublicKey * const public_ephemeral_key, //can be nullptr, if not nullptr, this will be a prekey message
			const PublicKey * const public_prekey) { //can be nullptr, if not nullptr, this will be a prekey message
		Expects((((public_identity_key != nullptr) && (public_prekey != nullptr))
					|| ((public_prekey == nullptr) && (public_identity_key == nullptr)))
				&& ((public_identity_key == nullptr) || !public_identity_key->empty)
				&& ((public_prekey == nullptr) || !public_prekey->empty));

		TRY_WITH_RESULT(send_data_result, this->ratchet.getSendData());
		const auto& send_data{send_data_result.value()};

		TRY_WITH_RESULT(header_result, header_construct(
				send_data.ephemeral,
				send_data.message_number,
				send_data.previous_message_number));
		auto header{header_result.value()};

		auto packet_type{molch_message_type::NORMAL_MESSAGE};
		auto prekey_metadata{std::make_optional<PrekeyMetadata>()};
		//check if this is a prekey message
		if (public_identity_key != nullptr) {
			packet_type = molch_message_type::PREKEY_MESSAGE;

			auto& metadata{prekey_metadata.value()};
			metadata.identity = *public_identity_key;
			metadata.ephemeral = *public_ephemeral_key;
			metadata.prekey = *public_prekey;
		}

		TRY_WITH_RESULT(encrypted_packet_result, packet_encrypt(
				packet_type,
				header,
				send_data.header_key,
				message,
				send_data.message_key,
				prekey_metadata));

		return encrypted_packet_result.value();
	}

	/*
	 * Try to decrypt a packet with skipped over header and message keys.
	 * This corresponds to "try_skipped_header_and_message_keys" from the
	 * Axolotl protocol description.
	 *
	 * Returns 0, if it was able to decrypt the packet.
	 */
	int Conversation::trySkippedHeaderAndMessageKeys(
			const span<const std::byte> packet,
			Buffer& message,
			uint32_t& receive_message_number,
			uint32_t& previous_receive_message_number) {
		//create buffers

		for (size_t index{0}; index < this->ratchet.skipped_header_and_message_keys.keys().size(); index++) {
			auto& node = this->ratchet.skipped_header_and_message_keys.keys()[index];
			auto decrypted_packet_result = packet_decrypt(
					packet,
					node.headerKey(),
					node.messageKey());
			if (decrypted_packet_result.has_value()) {
				auto& decrypted_packet{decrypted_packet_result.value()};
				message = std::move(decrypted_packet.message);
				this->ratchet.skipped_header_and_message_keys.remove(index);

				PublicKey their_signed_public_ephemeral;
				TRY_WITH_RESULT(extracted_header, header_extract(decrypted_packet.header));
				their_signed_public_ephemeral = extracted_header.value().their_public_ephemeral;
				receive_message_number = extracted_header.value().message_number;
				previous_receive_message_number = extracted_header.value().previous_message_number;
				return static_cast<int>(status_type::SUCCESS);
			}
		}

		return static_cast<int>(status_type::NOT_FOUND);
	}

	/*
	 * Receive and decrypt a message using an existing conversation.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	Buffer Conversation::receive(
			const span<const std::byte> packet, //received packet
			uint32_t& receive_message_number,
			uint32_t& previous_receive_message_number) {
		try {
			Buffer message;
			auto status{trySkippedHeaderAndMessageKeys(
					packet,
					message,
					receive_message_number,
					previous_receive_message_number)};
			if (status == static_cast<int>(status_type::SUCCESS)) {
				// found a key and successfully decrypted the message
				return message;
			}

			const auto receive_header_keys{this->ratchet.getReceiveHeaderKeys()};

			//try to decrypt the packet header with the current receive header key
			Buffer header;
			auto header_result = packet_decrypt_header(packet, receive_header_keys.current);
			if (header_result.has_value()) {
				header = std::move(header_result.value());
				TRY_VOID(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE));
			} else {
				auto header_result = packet_decrypt_header(packet, receive_header_keys.next);
				if (header_result.has_value()) {
					header = std::move(header_result.value());
					TRY_VOID(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE));
				} else {
					TRY_VOID(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::UNDECRYPTABLE));
					throw Exception{status_type::DECRYPT_ERROR, "Failed to decrypt the message."};
				}
			}

			//extract data from the header
			TRY_WITH_RESULT(extracted_header, header_extract(header));

			//and now decrypt the message with the message key
			//now we have all the data we need to advance the ratchet
			//so let's do that
			TRY_WITH_RESULT(message_key_result, this->ratchet.receive(
				extracted_header.value().their_public_ephemeral,
				extracted_header.value().message_number,
				extracted_header.value().previous_message_number));
			const auto& message_key{message_key_result.value()};

			TRY_WITH_RESULT(message_result, packet_decrypt_message(packet, message_key))
			message = std::move(message_result.value());

			this->ratchet.setLastMessageAuthenticity(true);

			receive_message_number = extracted_header.value().message_number;
			previous_receive_message_number = extracted_header.value().previous_message_number;

			return message;
		} catch (const std::exception&) {
			this->ratchet.setLastMessageAuthenticity(false);
			throw;
		}
	}

	ProtobufCConversation* Conversation::exportProtobuf(Arena& arena) const {
		//export the ratchet
		TRY_WITH_RESULT(exported_conversation_result, this->ratchet.exportProtobuf(arena));
		const auto& exported_conversation{exported_conversation_result.value()};

		//export the conversation id
		const auto& id{this->id_storage};
		protobuf_bytes_arena_export(arena, exported_conversation, id, CONVERSATION_ID_SIZE);

		return exported_conversation;
	}

	Conversation::Conversation(const ProtobufCConversation& conversation_protobuf) {
		//copy the id
		this->id_storage.set({
				uchar_to_byte(conversation_protobuf.id.data),
				conversation_protobuf.id.len});

		//import the ratchet
		TRY_WITH_RESULT(ratchet_result, Ratchet::import(conversation_protobuf));
		this->ratchet = std::move(ratchet_result.value());
	}

	const Key<CONVERSATION_ID_SIZE,KeyType::Key>& Conversation::id() const {
		return this->id_storage;
	}

	std::ostream& Conversation::print(std::ostream& stream) const {
		stream << "Conversation-ID:\n";
		this->id_storage.printHex(stream) << "\n";

		return stream;
	}
}
