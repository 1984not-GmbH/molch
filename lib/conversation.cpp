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

		TRY_WITH_RESULT(ratchet_result, Ratchet::create(
				our_private_identity,
				our_public_identity,
				their_public_identity,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_ephemeral));
		this->ratchet = std::move(ratchet_result.value());
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

		auto prekey_metadata{std::make_optional<PrekeyMetadata>()};
		auto& prekey_metadata_content{prekey_metadata.value()};
		prekey_metadata_content.identity = sender_public_identity;
		prekey_metadata_content.ephemeral = sender_public_ephemeral;
		prekey_metadata_content.prekey = receiver_public_prekey;
		TRY_WITH_RESULT(packet_result, this->send(message, prekey_metadata));
		packet = std::move(packet_result.value());
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

		TRY_WITH_RESULT(received_message_result, this->receive(packet));
		auto& received_message{received_message_result.value()};
		message = std::move(received_message.message);
	}

	result<Buffer> Conversation::send(const span<const std::byte> message, const std::optional<PrekeyMetadata>& prekey_metadata) {
		FulfillOrFail((not prekey_metadata.has_value())
			or ((not prekey_metadata.value().identity.empty)
				 and (not prekey_metadata.value().ephemeral.empty)
				 and (not prekey_metadata.value().prekey.empty)));

		OUTCOME_TRY(send_data, this->ratchet.getSendData());
		OUTCOME_TRY(header, header_construct(
				send_data.ephemeral,
				send_data.message_number,
				send_data.previous_message_number));

		auto packet_type{molch_message_type::NORMAL_MESSAGE};
		//check if this is a prekey message
		if (prekey_metadata.has_value()) {
			packet_type = molch_message_type::PREKEY_MESSAGE;
		}

		OUTCOME_TRY(encrypted_packet, packet_encrypt(
				packet_type,
				header,
				send_data.header_key,
				message,
				send_data.message_key,
				prekey_metadata));

		return encrypted_packet;
	}

	result<ReceivedMessage> Conversation::trySkippedHeaderAndMessageKeys(const span<const std::byte> packet) {
		for (size_t index{0}; index < this->ratchet.skipped_header_and_message_keys.keys().size(); index++) {
			auto& node = this->ratchet.skipped_header_and_message_keys.keys()[index];
			auto decrypted_packet_result = packet_decrypt(
					packet,
					node.headerKey(),
					node.messageKey());
			if (decrypted_packet_result.has_value()) {
				ReceivedMessage message;
				auto& decrypted_packet{decrypted_packet_result.value()};
				message.message = std::move(decrypted_packet.message);
				this->ratchet.skipped_header_and_message_keys.remove(index);

				PublicKey their_signed_public_ephemeral;
				OUTCOME_TRY(extracted_header, header_extract(decrypted_packet.header));
				message.message_number = extracted_header.message_number;
				message.previous_message_number = extracted_header.previous_message_number;

				return message;
			}
		}

		return Error(status_type::DECRYPT_ERROR, "No keys found for the packet.");
	}

	result<ReceivedMessage> Conversation::internal_receive(const span<const std::byte> packet) {
		printf("STARTING internal_receive\n");
		const auto received_message_result = trySkippedHeaderAndMessageKeys(packet);
		if (received_message_result.has_value()) {
			return received_message_result.value();
		}

		const auto receive_header_keys{this->ratchet.getReceiveHeaderKeys()};

		//try to decrypt the packet header with the current receive header key
		Buffer header;
		auto header_result = packet_decrypt_header(packet, receive_header_keys.current);
		if (header_result.has_value()) {
			header = std::move(header_result.value());
			OUTCOME_TRY(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::CURRENT_DECRYPTABLE));
		} else {
			auto header_result = packet_decrypt_header(packet, receive_header_keys.next);
			if (header_result.has_value()) {
				header = std::move(header_result.value());
				OUTCOME_TRY(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::NEXT_DECRYPTABLE));
			} else {
				OUTCOME_TRY(this->ratchet.setHeaderDecryptability(Ratchet::HeaderDecryptability::UNDECRYPTABLE));
				return Error(status_type::DECRYPT_ERROR, "Failed to decrypt the message.");
			}
		}

		//extract data from the header
		OUTCOME_TRY(extracted_header, header_extract(header));

		//and now decrypt the message with the message key
		//now we have all the data we need to advance the ratchet
		//so let's do that
		OUTCOME_TRY(message_key, this->ratchet.receive(
			extracted_header.their_public_ephemeral,
			extracted_header.message_number,
			extracted_header.previous_message_number));

		OUTCOME_TRY(message, packet_decrypt_message(packet, message_key));

		this->ratchet.setLastMessageAuthenticity(true);

		ReceivedMessage received_message;
		received_message.message = std::move(message);
		received_message.message_number = extracted_header.message_number;
		received_message.previous_message_number = extracted_header.previous_message_number;

		return received_message;
	}

	result<ReceivedMessage> Conversation::receive(const span<const std::byte> packet) {
		auto received_message_result = internal_receive(packet);
		if (not received_message_result.has_value()) {
			this->ratchet.setLastMessageAuthenticity(false);
		}

		return received_message_result;
	}

	result<ProtobufCConversation*> Conversation::exportProtobuf(Arena& arena) const {
		//export the ratchet
		OUTCOME_TRY(exported_conversation, this->ratchet.exportProtobuf(arena));

		//export the conversation id
		const auto& id{this->id_storage};
		outcome_protobuf_bytes_arena_export(arena, exported_conversation, id, CONVERSATION_ID_SIZE);

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
