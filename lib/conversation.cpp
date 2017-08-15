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
#include "molch.h"
#include "packet.hpp"
#include "header.hpp"
#include "molch-exception.hpp"
#include "destroyers.hpp"

ConversationT& ConversationT::move(ConversationT&& conversation) {
	if (this->id.cloneFrom(&conversation.id) != 0) {
		throw MolchException(BUFFER_ERROR, "Faild to clone id.");
	}
	this->ratchet = std::move(conversation.ratchet);

	return *this;
}

ConversationT::ConversationT(ConversationT&& conversation) {
	this->move(std::move(conversation));
}

ConversationT& ConversationT::operator=(ConversationT&& conversation) {
	return this->move(std::move(conversation));
}

/*
 * Create a new conversation.
 */
void ConversationT::create(
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral) {
	//check input
	if (!our_private_identity.contains(PRIVATE_KEY_SIZE)
			|| !our_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !their_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !our_public_ephemeral.contains(PRIVATE_KEY_SIZE)
			|| !our_public_ephemeral.contains(PUBLIC_KEY_SIZE)
			|| !their_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input for conversation_create.");
	}

	//create random id
	if (this->id.fillRandom(CONVERSATION_ID_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to create random conversation id.");
	}

	this->ratchet = std::make_unique<Ratchet>(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
}

ConversationT::ConversationT(
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& their_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_ephemeral) {
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
ConversationT::ConversationT(
		const Buffer& message, //message we want to send to the receiver
		std::unique_ptr<Buffer>& packet, //output
		const Buffer& sender_public_identity, //who is sending this message?
		const Buffer& sender_private_identity,
		const Buffer& receiver_public_identity,
		Buffer& receiver_prekey_list) { //PREKEY_AMOUNT * PUBLIC_KEY_SIZE
	uint32_t prekey_number;

	Buffer sender_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer sender_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	exception_on_invalid_buffer(sender_public_ephemeral);
	exception_on_invalid_buffer(sender_private_ephemeral);

	//check many error conditions
	if (!receiver_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !sender_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !sender_private_identity.contains(PRIVATE_KEY_SIZE)
			|| !receiver_prekey_list.contains((PREKEY_AMOUNT * PUBLIC_KEY_SIZE))) {
		throw MolchException(INVALID_INPUT, "Invalid input to conversation_start_send_conversation.");
	}

	//create an ephemeral keypair
	int status = crypto_box_keypair(sender_public_ephemeral.content, sender_private_ephemeral.content);
	if (status != 0) {
		throw MolchException(KEYGENERATION_FAILED, "Failed to generate ephemeral keypair.");
	}

	//choose a prekey
	prekey_number = randombytes_uniform(PREKEY_AMOUNT);
	Buffer receiver_public_prekey(
			&(receiver_prekey_list.content[prekey_number * PUBLIC_KEY_SIZE]),
			PUBLIC_KEY_SIZE);

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
ConversationT::ConversationT(
		const Buffer& packet, //received packet
		std::unique_ptr<Buffer>& message, //output
		const Buffer& receiver_public_identity,
		const Buffer& receiver_private_identity,
		PrekeyStore& receiver_prekeys) { //prekeys of the receiver
	uint32_t receive_message_number = 0;
	uint32_t previous_receive_message_number = 0;

	//key buffers
	Buffer receiver_public_prekey(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer receiver_private_prekey(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer sender_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer sender_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(receiver_public_prekey);
	exception_on_invalid_buffer(receiver_private_prekey);
	exception_on_invalid_buffer(sender_public_ephemeral);
	exception_on_invalid_buffer(sender_public_identity);

	if (!receiver_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !receiver_private_identity.contains(PRIVATE_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to conversation_start_receive_conversation.");
	}

	//get the senders keys and our public prekey from the packet
	molch_message_type packet_type;
	uint32_t current_protocol_version;
	uint32_t highest_supported_protocol_version;
	packet_get_metadata_without_verification(
		current_protocol_version,
		highest_supported_protocol_version,
		packet_type,
		packet,
		&sender_public_identity,
		&sender_public_ephemeral,
		&receiver_public_prekey);

	if (packet_type != PREKEY_MESSAGE) {
		throw MolchException(INVALID_VALUE, "Packet is not a prekey message.");
	}

	//get the private prekey that corresponds to the public prekey used in the message
	receiver_prekeys.getPrekey(receiver_public_prekey, receiver_private_prekey);

	this->create(
			receiver_private_identity,
			receiver_public_identity,
			sender_public_identity,
			receiver_private_prekey,
			receiver_public_prekey,
			sender_public_ephemeral);

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
std::unique_ptr<Buffer> ConversationT::send(
		const Buffer& message,
		const Buffer * const public_identity_key, //can be nullptr, if not nullptr, this will be a prekey message
		const Buffer * const public_ephemeral_key, //can be nullptr, if not nullptr, this will be a prekey message
		const Buffer * const public_prekey) { //can be nullptr, if not nullptr, this will be a prekey message
	molch_message_type packet_type;

	//create the header
	std::unique_ptr<Buffer> header;

	Buffer send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer send_message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	Buffer send_ephemeral_key(PUBLIC_KEY_SIZE, 0);
	exception_on_invalid_buffer(send_header_key);
	exception_on_invalid_buffer(send_message_key);
	exception_on_invalid_buffer(send_ephemeral_key);

	//ensure that either both public keys are nullptr or set
	if (((public_identity_key == nullptr) && (public_prekey != nullptr)) || ((public_prekey == nullptr) && (public_identity_key != nullptr))) {
		throw MolchException(INVALID_INPUT, "Invalid combination of provided key buffers.");
	}

	//check the size of the public keys
	if (((public_identity_key != nullptr) && !public_identity_key->contains(PUBLIC_KEY_SIZE)) || ((public_prekey != nullptr) && !public_prekey->contains(PUBLIC_KEY_SIZE))) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "Public key output has incorrect size.");
	}

	packet_type = NORMAL_MESSAGE;
	//check if this is a prekey message
	if (public_identity_key != nullptr) {
		packet_type = PREKEY_MESSAGE;
	}

	uint32_t send_message_number;
	uint32_t previous_send_message_number;
	this->ratchet->send(
			send_header_key,
			send_message_number,
			previous_send_message_number,
			send_ephemeral_key,
			send_message_key);

	header = header_construct(
			send_ephemeral_key,
			send_message_number,
			previous_send_message_number);

	return packet_encrypt(
			packet_type,
			*header,
			send_header_key,
			message,
			send_message_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
}

/*
 * Try to decrypt a packet with skipped over header and message keys.
 * This corresponds to "try_skipped_header_and_message_keys" from the
 * Axolotl protocol description.
 *
 * Returns 0, if it was able to decrypt the packet.
 */
int ConversationT::trySkippedHeaderAndMessageKeys(
		const Buffer& packet,
		std::unique_ptr<Buffer>& message,
		uint32_t& receive_message_number,
		uint32_t& previous_receive_message_number) {
	//create buffers
	std::unique_ptr<Buffer> header;
	Buffer their_signed_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	exception_on_invalid_buffer(their_signed_public_ephemeral);

	for (size_t index = 0; index < this->ratchet->skipped_header_and_message_keys.keys.size(); index++) {
		HeaderAndMessageKeyStoreNode& node = this->ratchet->skipped_header_and_message_keys.keys[index];
		bool decryption_successful = true;
		try {
			header = packet_decrypt_header(packet, node.header_key);
		} catch (const MolchException& exception) {
			decryption_successful = false;
		}
		if (decryption_successful) {
			try {
				message = packet_decrypt_message(packet, node.message_key);
			} catch (const MolchException& exception) {
				decryption_successful = false;
			}
			if (decryption_successful) {
				this->ratchet->skipped_header_and_message_keys.keys.erase(std::begin(this->ratchet->skipped_header_and_message_keys.keys) + static_cast<ptrdiff_t>(index));
				index--;

				header_extract(
						their_signed_public_ephemeral,
						receive_message_number,
						previous_receive_message_number,
						*header);
				return SUCCESS;
			}
		}
	}

	return NOT_FOUND;
}

/*
 * Receive and decrypt a message using an existing conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
std::unique_ptr<Buffer> ConversationT::receive(
		const Buffer& packet, //received packet
		uint32_t& receive_message_number,
		uint32_t& previous_receive_message_number) {
	try {
		bool decryptable = true;

		//create buffers
		std::unique_ptr<Buffer> header;

		Buffer current_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer their_signed_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
		exception_on_invalid_buffer(current_receive_header_key);
		exception_on_invalid_buffer(next_receive_header_key);
		exception_on_invalid_buffer(their_signed_public_ephemeral);
		exception_on_invalid_buffer(message_key);

		std::unique_ptr<Buffer> message;
		int status = trySkippedHeaderAndMessageKeys(
				packet,
				message,
				receive_message_number,
				previous_receive_message_number);
		if (status == SUCCESS) {
			// found a key and successfully decrypted the message
			return message;
		}

		this->ratchet->getReceiveHeaderKeys(current_receive_header_key, next_receive_header_key);

		//try to decrypt the packet header with the current receive header key
		try {
			header = packet_decrypt_header(packet, current_receive_header_key);
		} catch (const MolchException& exception) {
			decryptable = false;
		}
		if (decryptable) {
			this->ratchet->setHeaderDecryptability(CURRENT_DECRYPTABLE);
		} else {
			//since this failed, try to decrypt it with the next receive header key
			decryptable = true;
			try {
				header = packet_decrypt_header(packet, next_receive_header_key);
			} catch (const MolchException& exception) {
				decryptable = false;
			}
			if (decryptable) {
				this->ratchet->setHeaderDecryptability(NEXT_DECRYPTABLE);
			} else {
				this->ratchet->setHeaderDecryptability(UNDECRYPTABLE);
				throw MolchException(DECRYPT_ERROR, "Failed to decrypt the message.");
			}
		}

		//extract data from the header
		uint32_t local_receive_message_number;
		uint32_t local_previous_receive_message_number;
		header_extract(
				their_signed_public_ephemeral,
				local_receive_message_number,
				local_previous_receive_message_number,
				*header);

		//and now decrypt the message with the message key
		//now we have all the data we need to advance the ratchet
		//so let's do that
		this->ratchet->receive(
			message_key,
			their_signed_public_ephemeral,
			local_receive_message_number,
			local_previous_receive_message_number);

		message = packet_decrypt_message(packet, message_key);

		this->ratchet->setLastMessageAuthenticity(true);

		receive_message_number = local_receive_message_number;
		previous_receive_message_number = local_previous_receive_message_number;

		return message;
	} catch (const std::exception& exception) {
		this->ratchet->setLastMessageAuthenticity(false);
		throw exception;
	}
}

std::unique_ptr<Conversation,ConversationDeleter> ConversationT::exportProtobuf() const {
	std::unique_ptr<Conversation,ConversationDeleter> exported_conversation;
	unsigned char *id = nullptr;

	//export the ratchet
	exported_conversation = this->ratchet->exportProtobuf();

	//export the conversation id
	id = throwing_zeroed_malloc<unsigned char>(CONVERSATION_ID_SIZE);
	if (this->id.cloneToRaw(id, CONVERSATION_ID_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy conversation id.");
	}
	exported_conversation->id.data = id;
	exported_conversation->id.len = CONVERSATION_ID_SIZE;

	return exported_conversation;
}

ConversationT::ConversationT(const Conversation& conversation_protobuf) {
	//copy the id
	if (this->id.cloneFromRaw(conversation_protobuf.id.data, conversation_protobuf.id.len) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy id.");
	}

	//import the ratchet
	this->ratchet = std::make_unique<Ratchet>(conversation_protobuf);
}

std::ostream& ConversationT::print(std::ostream& stream) const {
	stream << "Conversation-ID:\n";
	stream << this->id.toHex() << "\n";

	return stream;
}

