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

#include <algorithm>
#include <exception>

#include "packet.hpp"
#include "constants.h"
#include "protobuf.hpp"
#include "gsl.hpp"

namespace Molch {
	constexpr size_t padding_blocksize{255};

	/*!
	 * Convert molch_message_type to PacketHeader__PacketType.
	 */
	static constexpr Molch__Protobuf__PacketHeader__PacketType to_packet_header_packet_type(const molch_message_type packet_type) {
		switch (packet_type) {
			case molch_message_type::PREKEY_MESSAGE:
				return MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE;
			case molch_message_type::NORMAL_MESSAGE:
				return MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE;
			case molch_message_type::INVALID:
			default:
				//fallback to normal message
				return MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE;
		}
	}

	/*!
	 * Convert PacketHeader__PacketType to molch_message_type.
	 */
	static constexpr molch_message_type to_molch_message_type(const Molch__Protobuf__PacketHeader__PacketType packet_type) {
		switch (packet_type) {
			case MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE:
				return molch_message_type::NORMAL_MESSAGE;
			case MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE:
				return molch_message_type::PREKEY_MESSAGE;
			case _MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE_IS_INT_SIZE:
			default:
				return molch_message_type::INVALID;
		}
	}

	/*!
	 * Unpacks a packet via Protobuf-C into a struct and verifies that all the necessary
	 * fields exist.
	 *
	 * \param packet
	 *   The binary packet.
	 *
	 * \return
	 *   The unpacked struct.
	 */
	static result<std::unique_ptr<ProtobufCPacket,PacketDeleter>> packet_unpack(const span<const std::byte> packet) {
		//unpack the packet
		auto packet_struct{std::unique_ptr<ProtobufCPacket,PacketDeleter>(molch__protobuf__packet__unpack(&protobuf_c_allocator, packet.size(), byte_to_uchar(packet.data())))};
		if (!packet_struct) {
			return Error(status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");
		}

		if (packet_struct->packet_header->current_protocol_version != 0) {
			return Error(status_type::UNSUPPORTED_PROTOCOL_VERSION, "The packet has an unsuported protocol version.");
		}

		//check if the packet contains the necessary fields
		if (!packet_struct->has_encrypted_axolotl_header
			|| !packet_struct->has_encrypted_message
			|| !packet_struct->packet_header->has_packet_type
			|| !packet_struct->packet_header->has_header_nonce
			|| !packet_struct->packet_header->has_message_nonce) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "Some fields are missing in the packet.");
		}

		//check the size of the nonces
		if ((packet_struct->packet_header->header_nonce.len != HEADER_NONCE_SIZE)
			|| (packet_struct->packet_header->message_nonce.len != MESSAGE_NONCE_SIZE)) {
			return Error(status_type::INCORRECT_BUFFER_SIZE, "At least one of the nonces has an incorrect length.");
		}

		if (packet_struct->packet_header->packet_type == MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
			//check if the public keys for prekey messages are there
			if (!packet_struct->packet_header->has_public_identity_key
				|| !packet_struct->packet_header->has_public_ephemeral_key
				|| !packet_struct->packet_header->has_public_prekey) {
				return Error(status_type::PROTOBUF_MISSING_ERROR, "The prekey packet misses at least one public key.");
			}

			//check the sizes of the public keys
			if ((packet_struct->packet_header->public_identity_key.len != PUBLIC_KEY_SIZE)
				|| (packet_struct->packet_header->public_ephemeral_key.len != PUBLIC_KEY_SIZE)
				|| (packet_struct->packet_header->public_prekey.len != PUBLIC_KEY_SIZE)) {
				return Error(status_type::INCORRECT_BUFFER_SIZE, "At least one of the public keys of the prekey packet has an incorrect length.");
			}
		}

		return packet_struct;
	}

	Buffer packet_encrypt(
			//inputs
			const molch_message_type packet_type,
			const span<const std::byte> axolotl_header,
			const HeaderKey& axolotl_header_key,
			const span<const std::byte> message,
			const MessageKey& message_key,
			//optional inputs (prekey messages only)
			const PublicKey * const public_identity_key,
			const PublicKey * const public_ephemeral_key,
			const PublicKey * const public_prekey) {
		Expects((packet_type != molch_message_type::INVALID)
			&& !axolotl_header_key.empty
			&& !message_key.empty);

		//initialize the protobuf structs
		ProtobufCPacket packet_struct;
		molch__protobuf__packet__init(&packet_struct);
		ProtobufCPacketHeader packet_header_struct;
		molch__protobuf__packet_header__init(&packet_header_struct);
		packet_struct.packet_header = &packet_header_struct;

		//set the protocol version
		packet_header_struct.current_protocol_version = 0;
		packet_header_struct.highest_supported_protocol_version = 0;

		//set the packet type
		packet_header_struct.has_packet_type = true;
		packet_header_struct.packet_type = to_packet_header_packet_type(packet_type);

		if (packet_type == molch_message_type::PREKEY_MESSAGE) {
			Expects((public_identity_key != nullptr) && !public_identity_key->empty
				&& (public_ephemeral_key != nullptr) && !public_ephemeral_key->empty
				&& (public_prekey != nullptr) && !public_prekey->empty);

			//set the public identity key
			packet_header_struct.has_public_identity_key = true;
			packet_header_struct.public_identity_key.data = const_cast<uint8_t*>(byte_to_uchar(public_identity_key->data()));
			packet_header_struct.public_identity_key.len = public_identity_key->size();

			//set the public ephemeral key
			packet_header_struct.has_public_ephemeral_key = true;
			packet_header_struct.public_ephemeral_key.data = const_cast<uint8_t*>(byte_to_uchar(public_ephemeral_key->data()));
			packet_header_struct.public_ephemeral_key.len = public_ephemeral_key->size();

			//set the public prekey
			packet_header_struct.has_public_prekey = true;
			packet_header_struct.public_prekey.data = const_cast<uint8_t*>(byte_to_uchar(public_prekey->data()));
			packet_header_struct.public_prekey.len = public_prekey->size();
		}

		//generate the header nonce and add it to the packet header
		Buffer header_nonce{HEADER_NONCE_SIZE, 0};
		TRY_VOID(header_nonce.fillRandom(HEADER_NONCE_SIZE));
		packet_header_struct.has_header_nonce = true;
		packet_header_struct.header_nonce.data = byte_to_uchar(header_nonce.data());
		packet_header_struct.header_nonce.len = header_nonce.size();

		//encrypt the header
		Buffer encrypted_axolotl_header{
			axolotl_header.size() + crypto_secretbox_MACBYTES,
			axolotl_header.size() + crypto_secretbox_MACBYTES};
		TRY_VOID(crypto_secretbox_easy(
				encrypted_axolotl_header,
				axolotl_header,
				header_nonce,
				axolotl_header_key));

		//add the encrypted header to the protobuf struct
		packet_struct.has_encrypted_axolotl_header = true;
		packet_struct.encrypted_axolotl_header.data = byte_to_uchar(encrypted_axolotl_header.data());
		packet_struct.encrypted_axolotl_header.len = encrypted_axolotl_header.size();

		//generate the message nonce and add it to the packet header
		Buffer message_nonce{MESSAGE_NONCE_SIZE, 0};
		TRY_VOID(message_nonce.fillRandom(MESSAGE_NONCE_SIZE));
		packet_header_struct.has_message_nonce = true;
		packet_header_struct.message_nonce.data = byte_to_uchar(message_nonce.data());
		packet_header_struct.message_nonce.len = message_nonce.size();

		//pad the message (ISO/IEC 7816-4 padding to 255 byte blocks)
		size_t padding_amount{padding_blocksize - (message.size() % padding_blocksize)};
		Buffer padded_message{message.size() + padding_amount, 0};
		TRY_VOID(padded_message.cloneFromRaw(message));
		TRY_VOID(padded_message.setSize(padded_message.capacity()));
		TRY_WITH_RESULT(result, sodium_pad(padded_message, message.size(), 255));
		auto padded_span{result.value()};
		if (padded_span.size() != padded_message.size()) {
			throw Exception{status_type::GENERIC_ERROR, "Padding doesn't have the expected size."};
		}

		//encrypt the message
		Buffer encrypted_message{
			padded_message.size() + crypto_secretbox_MACBYTES,
			padded_message.size() + crypto_secretbox_MACBYTES};
		TRY_VOID(crypto_secretbox_easy(
				encrypted_message,
				padded_message,
				message_nonce,
				message_key));

		//add the encrypted message to the protobuf struct
		packet_struct.has_encrypted_message = true;
		packet_struct.encrypted_message.data = byte_to_uchar(encrypted_message.data());
		packet_struct.encrypted_message.len = encrypted_message.size();

		//calculate the required length
		const size_t packed_length{molch__protobuf__packet__get_packed_size(&packet_struct)};
		//pack the packet
		Buffer packet{packed_length, 0};
		TRY_VOID(packet.setSize(molch__protobuf__packet__pack(&packet_struct, byte_to_uchar(packet.data()))));
		if (packet.size() != packed_length) {
			throw Exception{status_type::PROTOBUF_PACK_ERROR, "Packet packet has incorrect length."};
		}

		return packet;
	}

	void packet_decrypt(
			//outputs
			uint32_t& current_protocol_version,
			uint32_t& highest_supported_protocol_version,
			molch_message_type& packet_type,
			std::optional<Buffer>& axolotl_header,
			std::optional<Buffer>& message,
			//inputs
			const span<const std::byte> packet,
			const HeaderKey& axolotl_header_key,
			const MessageKey& message_key, //MESSAGE_KEY_SIZE
			//optional outputs (prekey messages only)
			PublicKey * const public_identity_key,
			PublicKey * const public_ephemeral_key,
			PublicKey * const public_prekey) {
		//get metadata
		TRY_WITH_RESULT(unverified_metadata_result, packet_get_metadata_without_verification(packet));
		const auto& unverified_metadata{unverified_metadata_result.value()};

		//decrypt the header
		axolotl_header = packet_decrypt_header(packet, axolotl_header_key);

		//decrypt the message
		message = packet_decrypt_message(packet, message_key);

		current_protocol_version = unverified_metadata.current_protocol_version;
		highest_supported_protocol_version = unverified_metadata.highest_supported_protocol_version;
		packet_type = unverified_metadata.packet_type;

		if ((public_identity_key != nullptr) || (public_ephemeral_key != nullptr) || (public_prekey != nullptr)) {
			if (not unverified_metadata.prekey_metadata.has_value()) {
				throw Molch::Exception(status_type::INVALID_VALUE, "No prekey metadata found.");
			}
			const auto& prekey_metadata{unverified_metadata.prekey_metadata.value()};
			if (public_identity_key != nullptr) {
				*public_identity_key = prekey_metadata.identity;
			}
			if (public_ephemeral_key != nullptr) {
				*public_ephemeral_key = prekey_metadata.ephemeral;
			}
			if (public_prekey != nullptr) {
				*public_prekey = prekey_metadata.prekey;
			}
		}
	}

	result<Metadata> packet_get_metadata_without_verification(const span<const std::byte> packet) {
		OUTCOME_TRY(packet_struct, packet_unpack(packet));

		Metadata metadata;
		if (packet_struct->packet_header->packet_type == MOLCH__PROTOBUF__PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
			metadata.prekey_metadata = PrekeyMetadata();
			auto& prekey_metadata{metadata.prekey_metadata.value()};
			//copy the public keys
			prekey_metadata.identity.set({
					uchar_to_byte(packet_struct->packet_header->public_identity_key.data),
					packet_struct->packet_header->public_identity_key.len});
			prekey_metadata.ephemeral.set({
					uchar_to_byte(packet_struct->packet_header->public_ephemeral_key.data),
					packet_struct->packet_header->public_ephemeral_key.len});
			prekey_metadata.prekey.set({
					uchar_to_byte(packet_struct->packet_header->public_prekey.data),
					packet_struct->packet_header->public_prekey.len});
		}

		metadata.current_protocol_version = packet_struct->packet_header->current_protocol_version;
		metadata.highest_supported_protocol_version = packet_struct->packet_header->highest_supported_protocol_version;
		metadata.packet_type = to_molch_message_type(packet_struct->packet_header->packet_type);

		return metadata;
	}

	std::optional<Buffer> packet_decrypt_header(
			const span<const std::byte> packet,
			const HeaderKey& axolotl_header_key) {

		//check input
		if (axolotl_header_key.empty) {
			return std::nullopt;
		}

		const auto packet_struct_result = packet_unpack(packet);
		if (not packet_struct_result.has_value()) {
			return std::nullopt;
		}
		const auto& packet_struct{packet_struct_result.value()};

		if (packet_struct->encrypted_axolotl_header.len < crypto_secretbox_MACBYTES) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "The ciphertext of the axolotl header is too short."};
		}

		const size_t axolotl_header_length{packet_struct->encrypted_axolotl_header.len - crypto_secretbox_MACBYTES};
		auto axolotl_header{std::make_optional<Buffer>(axolotl_header_length, axolotl_header_length)};

		if (!crypto_secretbox_open_easy(
				*axolotl_header,
				{uchar_to_byte(packet_struct->encrypted_axolotl_header.data), packet_struct->encrypted_axolotl_header.len},
				{uchar_to_byte(packet_struct->packet_header->header_nonce.data), packet_struct->packet_header->header_nonce.len},
				axolotl_header_key)) {
			return std::nullopt;
		}

		return axolotl_header;
	}

	std::optional<Buffer> packet_decrypt_message(const span<const std::byte> packet, const MessageKey& message_key) {
		//check input
		if (message_key.empty) {
			return std::nullopt;
		}

		const auto packet_struct_result = packet_unpack(packet);
		if (not packet_struct_result.has_value()) {
			return std::nullopt;
		}
		const auto& packet_struct{packet_struct_result.value()};

		if (packet_struct->encrypted_message.len < crypto_secretbox_MACBYTES) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "The ciphertext of the message is too short."};
		}

		const size_t padded_message_length{packet_struct->encrypted_message.len - crypto_secretbox_MACBYTES};
		if (padded_message_length < padding_blocksize) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "The padded message is too short."};
		}
		auto padded_message{std::make_optional<Buffer>(padded_message_length, padded_message_length)};

		if (!crypto_secretbox_open_easy(
				*padded_message,
				{uchar_to_byte(packet_struct->encrypted_message.data), packet_struct->encrypted_message.len},
				{uchar_to_byte(packet_struct->packet_header->message_nonce.data), packet_struct->packet_header->message_nonce.len},
				message_key)) {
			return std::nullopt;
		}

		//undo the padding
		TRY_WITH_RESULT(result3, sodium_unpad(*padded_message, padding_blocksize));
		auto unpadded_span{result3.value()};
		TRY_VOID(padded_message->setSize(unpadded_span.size()));

		return padded_message;
	}
}
