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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <memory>
#include <iostream>

#include "utils.hpp"
#include "../include/molch.h"
#include "../lib/user-store.hpp" //for PREKEY_AMOUNT
#include "../lib/destroyers.hpp"
#include "../lib/malloc.hpp"

using namespace Molch;

static span<std::byte> decrypt_conversation_backup(
		Arena& pool,
		const span<const std::byte> backup,
		const span<const std::byte> backup_key) {
	Expects(!backup.empty() && (backup_key.size() == BACKUP_KEY_SIZE));

	//unpack the encrypted backup
	auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup.size(), byte_to_uchar(backup.data())))};
	if (encrypted_backup_struct == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Backup is not a conversation backup."};
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw Molch::Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state."};
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		throw Molch::Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
	}

	auto decrypted_backup_content{pool.allocate<std::byte>(
			encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
	span<std::byte> decrypted_backup{
		decrypted_backup_content,
		encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES};

	//decrypt the backup
	auto status{crypto_secretbox_open_easy(
			byte_to_uchar(decrypted_backup.data()),
			encrypted_backup_struct->encrypted_backup.data,
			encrypted_backup_struct->encrypted_backup.len,
			encrypted_backup_struct->encrypted_backup_nonce.data,
			byte_to_uchar(backup_key.data()))};
	if (status != 0) {
		throw Molch::Exception{status_type::DECRYPT_ERROR, "Failed to decrypt conversation backup."};
	}

	return decrypted_backup;
}

static span<std::byte> decrypt_full_backup(
		Arena& pool,
		const span<const std::byte> backup,
		const span<const std::byte> backup_key) {
	//check input
	Expects(!backup.empty() && (backup_key.size() == BACKUP_KEY_SIZE));

	//unpack the encrypted backup
	auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup.size(), byte_to_uchar(backup.data())))};
	if (encrypted_backup_struct == nullptr) {
		throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Backup is not a conversation backup."};
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw Molch::Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state."};
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		throw Molch::Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
	}

	auto decrypted_backup_content{pool.allocate<std::byte>(
		encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
	span<std::byte> decrypted_backup{
		decrypted_backup_content,
		encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES};

	//decrypt the backup
	auto status{crypto_secretbox_open_easy(
			byte_to_uchar(decrypted_backup.data()),
			encrypted_backup_struct->encrypted_backup.data,
			encrypted_backup_struct->encrypted_backup.len,
			encrypted_backup_struct->encrypted_backup_nonce.data,
			byte_to_uchar(backup_key.data()))};
	if (status != 0) {
		throw Molch::Exception{status_type::DECRYPT_ERROR, "Failed to decrypt conversation backup."};
	}

	return decrypted_backup;
}

int main() {
	try {
		Molch::sodium_init();

		//mustn't crash here!
		molch_destroy_all_users();

		Buffer backup_key{BACKUP_KEY_SIZE, BACKUP_KEY_SIZE};
		{
			return_status status{molch_update_backup_key(byte_to_uchar(backup_key.data()), backup_key.size())};
			on_error {
				throw Molch::Exception{status};
			}
		}

		//check user count
		if (molch_user_count() != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong user count."};
		}

		//create a new user
		Buffer new_backup_key{BACKUP_KEY_SIZE, BACKUP_KEY_SIZE};
		Buffer alice_public_identity{PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE};
		Buffer alice_head_on_keyboard{"mn ujkhuzn7b7bzh6ujg7j8hn"};
		size_t complete_export_length{0};
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> complete_export;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> alice_public_prekeys;
		size_t alice_public_prekeys_length{0};
		{
			unsigned char *complete_export_ptr{nullptr};
			unsigned char *alice_public_prekeys_ptr{nullptr};
			auto status{molch_create_user(
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size(),
					&alice_public_prekeys_ptr,
					&alice_public_prekeys_length,
					byte_to_uchar(new_backup_key.data()),
					new_backup_key.size(),
					&complete_export_ptr,
					&complete_export_length,
					byte_to_uchar(alice_head_on_keyboard.data()),
					alice_head_on_keyboard.size())};
			on_error {
				throw Molch::Exception{status};
			}
			complete_export.reset(complete_export_ptr);
			alice_public_prekeys.reset(alice_public_prekeys_ptr);
		}

		if (backup_key == new_backup_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "New backup key is the same as the old one."};
		}

		backup_key.cloneFrom(new_backup_key);

		printf("Alice public identity (%zu Bytes):\n", alice_public_identity.size());
		alice_public_identity.printHex(std::cout) << std::endl;
		if (!complete_export) {
			throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export the librarys state after creating alice."};
		}


		//check user count
		if (molch_user_count() != 1) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong user count."};
		}

		//create a new backup key
		{
			return_status status{molch_update_backup_key(byte_to_uchar(backup_key.data()), backup_key.size())};
			on_error {
				throw Molch::Exception{status};
			}
		}

		printf("Updated backup key:\n");
		backup_key.printHex(std::cout) << std::endl;

		//create another user
		Buffer bob_public_identity{PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE};
		Buffer bob_head_on_keyboard{"jnu8h77z6ht56ftgnujh"};
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> bob_public_prekeys;
		size_t bob_public_prekeys_length{0};
		{
			unsigned char *bob_public_prekeys_ptr{nullptr};
			auto status{molch_create_user(
					byte_to_uchar(bob_public_identity.data()),
					bob_public_identity.size(),
					&bob_public_prekeys_ptr,
					&bob_public_prekeys_length,
					byte_to_uchar(backup_key.data()),
					backup_key.size(),
					nullptr,
					nullptr,
					byte_to_uchar(bob_head_on_keyboard.data()),
					bob_head_on_keyboard.size())};
			on_error {
				throw Molch::Exception{status};
			}
			bob_public_prekeys.reset(bob_public_prekeys_ptr);
		}

		printf("Bob public identity (%zu Bytes):\n", bob_public_identity.size());
		bob_public_identity.printHex(std::cout) << std::endl;

		//check user count
		if (molch_user_count() != 2) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong user count."};
		}

		//check user list
		size_t user_count{0};
		size_t user_list_length{0};
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> user_list;
		{
			unsigned char *user_list_ptr{nullptr};
			auto status{molch_list_users(&user_list_ptr, &user_list_length, &user_count)};
			on_error {
				throw Molch::Exception{status};
			}
			user_list.reset(user_list_ptr);
		}
		if ((user_count != 2) || (user_list_length != user_count * PUBLIC_KEY_SIZE)
				|| (sodium_memcmp(alice_public_identity.data(), user_list.get(), alice_public_identity.size()) != 0)
				|| (sodium_memcmp(bob_public_identity.data(), user_list.get() + PUBLIC_KEY_SIZE, alice_public_identity.size()) != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User list is incorrect."};
		}

		//create a new send conversation (alice sends to bob)
		Buffer alice_conversation{CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE};
		Buffer alice_send_message{"Hi Bob. Alice here!"};
		size_t alice_send_packet_length;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> alice_send_packet;
		{
			unsigned char * alice_send_packet_ptr{nullptr};
			auto status{molch_start_send_conversation(
					byte_to_uchar(alice_conversation.data()),
					alice_conversation.size(),
					&alice_send_packet_ptr,
					&alice_send_packet_length,
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size(),
					byte_to_uchar(bob_public_identity.data()),
					bob_public_identity.size(),
					bob_public_prekeys.get(),
					bob_public_prekeys_length,
					byte_to_uchar(alice_send_message.data()),
					alice_send_message.size(),
					nullptr,
					nullptr)};
			on_error {
				throw Molch::Exception{status};
			}
			alice_send_packet.reset(alice_send_packet_ptr);
		}

		//check conversation export
		size_t number_of_conversations{0};
		size_t conversation_list_length{0};
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> conversation_list;
		{
			unsigned char *conversation_list_ptr{nullptr};
			auto status{molch_list_conversations(
					&conversation_list_ptr,
					&conversation_list_length,
					&number_of_conversations,
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size())};
			on_error {
				throw Molch::Exception{status};
			}
			conversation_list.reset(conversation_list_ptr);
		}
		if ((number_of_conversations != 1) || (alice_conversation.compareToRaw({uchar_to_byte(conversation_list.get()), conversation_list_length}) != 0)) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to list conversations."};
		}

		//check the message type
		if (molch_get_message_type(alice_send_packet.get(), alice_send_packet_length) != molch_message_type::PREKEY_MESSAGE) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong message type."};
		}

		// export the prekeys again
		{
			unsigned char *alice_public_prekeys_ptr{nullptr};
			auto status{molch_get_prekey_list(
					&alice_public_prekeys_ptr,
					&alice_public_prekeys_length,
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size())};
			on_error {
				throw Molch::Exception{status};
			}
			alice_public_prekeys.reset(alice_public_prekeys_ptr);
		}

		//create a new receive conversation (bob receives from alice)
		Buffer bob_conversation{CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE};
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> bob_receive_message;
		size_t bob_receive_message_length;
		{
			unsigned char *bob_receive_message_ptr{nullptr};
			unsigned char *bob_public_prekeys_ptr{nullptr};
			auto status{molch_start_receive_conversation(
					byte_to_uchar(bob_conversation.data()),
					bob_conversation.size(),
					&bob_public_prekeys_ptr,
					&bob_public_prekeys_length,
					&bob_receive_message_ptr,
					&bob_receive_message_length,
					byte_to_uchar(bob_public_identity.data()),
					bob_public_identity.size(),
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size(),
					alice_send_packet.get(),
					alice_send_packet_length,
					nullptr,
					nullptr)};
			on_error {
				throw Molch::Exception{status};
			}
			bob_receive_message.reset(bob_receive_message_ptr);
			bob_public_prekeys.reset(bob_public_prekeys_ptr);
		}

		//compare sent and received messages
		printf("sent (Alice): %.*s\n", static_cast<int>(alice_send_message.size()), byte_to_uchar(alice_send_message.data()));
		printf("received (Bob): %.*s\n", static_cast<int>(bob_receive_message_length), bob_receive_message.get());
		if ((alice_send_message.size() != bob_receive_message_length)
				|| (sodium_memcmp(alice_send_message.data(), bob_receive_message.get(), bob_receive_message_length) != 0)) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Incorrect message received."};
		}

		//bob replies
		Buffer bob_send_message{"Welcome Alice!"};
		size_t bob_send_packet_length;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> conversation_export;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> bob_send_packet;
		size_t conversation_export_length{0};
		{
			unsigned char *bob_send_packet_ptr{nullptr};
			unsigned char *conversation_export_ptr{nullptr};
			auto status{molch_encrypt_message(
					&bob_send_packet_ptr,
					&bob_send_packet_length,
					byte_to_uchar(bob_conversation.data()),
					bob_conversation.size(),
					byte_to_uchar(bob_send_message.data()),
					bob_send_message.size(),
					&conversation_export_ptr,
					&conversation_export_length)};
			on_error {
				throw Molch::Exception{status};
			}
			conversation_export.reset(conversation_export_ptr);
			bob_send_packet.reset(bob_send_packet_ptr);
		}

		if (conversation_export == nullptr) {
			throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export the conversation after encrypting a message."};
		}

		//check the message type
		if (molch_get_message_type(bob_send_packet.get(), bob_send_packet_length) != molch_message_type::NORMAL_MESSAGE) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong message type."};
		}

		//alice receives reply
		uint32_t alice_receive_message_number{UINT32_MAX};
		uint32_t alice_previous_receive_message_number{UINT32_MAX};
		size_t alice_receive_message_length;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> alice_receive_message;
		{
			unsigned char *alice_receive_message_ptr{nullptr};
			auto status{molch_decrypt_message(
					&alice_receive_message_ptr,
					&alice_receive_message_length,
					&alice_receive_message_number,
					&alice_previous_receive_message_number,
					byte_to_uchar(alice_conversation.data()),
					alice_conversation.size(),
					bob_send_packet.get(),
					bob_send_packet_length,
					nullptr,
					nullptr)};
			on_error {
				throw Molch::Exception{status};
			}
			alice_receive_message.reset(alice_receive_message_ptr);
		}

		if ((alice_receive_message_number != 0) || (alice_previous_receive_message_number != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Incorrect receive message number for Alice."};
		}

		//compare sent and received messages
		printf("sent (Bob): %.*s\n", static_cast<int>(bob_send_message.size()), byte_to_uchar(bob_send_message.data()));
		printf("received (Alice): %.*s\n", static_cast<int>(alice_receive_message_length), alice_receive_message.get());
		if ((bob_send_message.size() != alice_receive_message_length)
				|| (sodium_memcmp(bob_send_message.data(), alice_receive_message.get(), alice_receive_message_length) != 0)) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Incorrect message received."};
		}

		//test export
		printf("Test export!\n");
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> backup;
		size_t backup_length;
		{
			unsigned char *backup_ptr{nullptr};
			auto status{molch_export(&backup_ptr, &backup_length)};
			on_error {
				throw Molch::Exception{status};
			}
			backup.reset(backup_ptr);
		}

		//test import
		printf("Test import!\n");
		{
			auto status{molch_import(
					byte_to_uchar(new_backup_key.data()),
					new_backup_key.size(),
					backup.get(),
					backup_length,
					byte_to_uchar(backup_key.data()),
					backup_key.size())};
			on_error {
				throw Molch::Exception{status};
			}
		}

		Arena pool;
		auto decrypted_backup{decrypt_full_backup(
				pool,
				{uchar_to_byte(backup.get()), backup_length},
				backup_key)};

		//compare the keys
		if (backup_key == new_backup_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "New backup key expected."};
		}

		//copy the backup key
		backup_key.cloneFrom(new_backup_key);

		//now export again
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> imported_backup;
		size_t imported_backup_length;
		{
			unsigned char* imported_backup_ptr{nullptr};
			auto status{molch_export(&imported_backup_ptr, &imported_backup_length)};
			on_error {
				throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export imported backup."};
			}
			imported_backup.reset(imported_backup_ptr);
		}

		auto decrypted_imported_backup{decrypt_full_backup(
				pool,
				{uchar_to_byte(imported_backup.get()), imported_backup_length},
				backup_key)};

		//compare
		if (decrypted_backup != decrypted_imported_backup) {
			throw Molch::Exception{status_type::IMPORT_ERROR, "Imported backup is incorrect."};
		}

		//test conversation export
		{
			unsigned char *backup_ptr{nullptr};
			auto status{molch_conversation_export(
					&backup_ptr,
					&backup_length,
					byte_to_uchar(alice_conversation.data()),
					alice_conversation.size())};
			on_error {
				throw Molch::Exception{status};
			}
			backup.reset(backup_ptr);
		}

		printf("Alice' conversation exported!\n");

		//import again
		{
			auto status{molch_conversation_import(
					byte_to_uchar(new_backup_key.data()),
					new_backup_key.size(),
					backup.get(),
					backup_length,
					byte_to_uchar(backup_key.data()),
					backup_key.size())};
			on_error {
				throw Molch::Exception{status};
			}
		}

		auto decrypted_conversation_backup{decrypt_conversation_backup(
				pool,
				{uchar_to_byte(backup.get()), backup_length},
				backup_key)};

		//copy the backup key
		backup_key.cloneFrom(new_backup_key);


		//export again
		{
			unsigned char *imported_backup_ptr{nullptr};
			auto status{molch_conversation_export(
					&imported_backup_ptr,
					&imported_backup_length,
					byte_to_uchar(alice_conversation.data()),
					alice_conversation.size())};
			on_error {
				throw Molch::Exception{status};
			}
			imported_backup.reset(imported_backup_ptr);
		}

		auto decrypted_imported_conversation_backup{decrypt_conversation_backup(
				pool,
				{uchar_to_byte(imported_backup.get()), imported_backup_length},
				backup_key)};

		//compare
		if (decrypted_conversation_backup != decrypted_imported_conversation_backup) {
			throw Molch::Exception{status_type::IMPORT_ERROR, "Protobuf of imported conversation is incorrect."};
		}

		//destroy the conversations
		{
			auto status{molch_end_conversation(byte_to_uchar(alice_conversation.data()), alice_conversation.size(), nullptr, nullptr)};
			on_error {
				throw Molch::Exception{status};
			}
		}
		{
			auto status{molch_end_conversation(byte_to_uchar(bob_conversation.data()), bob_conversation.size(), nullptr, nullptr)};
			on_error {
				throw Molch::Exception{status};
			}
		}

		//check if conversation has ended
		number_of_conversations = 0;
		conversation_list_length = 0;
		{
			unsigned char *conversation_list_ptr{nullptr};
			auto status{molch_list_conversations(
					&conversation_list_ptr,
					&conversation_list_length,
					&number_of_conversations,
					byte_to_uchar(alice_public_identity.data()),
					alice_public_identity.size())};
			on_error {
				throw Molch::Exception{status};
			}
			conversation_list.reset(conversation_list_ptr);
		}
		if ((number_of_conversations != 0) || conversation_list) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to end conversation."};
		}
		printf("Alice' conversation has ended successfully.\n");

		//destroy the users again
		molch_destroy_all_users();

		//check user count
		if (molch_user_count() != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Wrong user count."};
		}

		//TODO check detection of invalid prekey list signatures and old timestamps + more scenarios

		Buffer success_buffer{"SUCCESS"};
		size_t printed_status_length{0};
		auto printed_status{std::unique_ptr<unsigned char,MallocDeleter<unsigned char>>(reinterpret_cast<unsigned char*>(molch_print_status(&printed_status_length, return_status_init())))};
		if (success_buffer.compareToRaw({uchar_to_byte(printed_status.get()), printed_status_length}) != 0) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "molch_print_status produces incorrect output."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
