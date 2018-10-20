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
#include <iostream>
#include <string>
#include <encrypted_backup.pb-c.h>
#include <cstring>

#include "integration-utils.hpp"
#include "inline-utils.hpp"
#include "../include/molch.h"

static ProtobufCAllocator protobuf_c_allocator = {
		[]([[maybe_unused]] void* userdata, size_t size) -> void* {
			return malloc(size); //NOLINT
        },
		[]([[maybe_unused]] void* userdata, void* pointer) {
			free(pointer); //NOLINT
        },
		nullptr
};

struct AutoFreeEncryptedBackup {
	AutoFreeEncryptedBackup() = default;
	AutoFreeEncryptedBackup(Molch__Protobuf__EncryptedBackup* protobuf) : protobuf{protobuf} {}
	AutoFreeEncryptedBackup(const AutoFreeEncryptedBackup&) = delete;
	AutoFreeEncryptedBackup(AutoFreeEncryptedBackup&&) = delete;
	AutoFreeEncryptedBackup& operator=(const AutoFreeEncryptedBackup&) = delete;
	AutoFreeEncryptedBackup& operator=(AutoFreeEncryptedBackup&&) = delete;

	Molch__Protobuf__EncryptedBackup* protobuf;

	~AutoFreeEncryptedBackup() {
	    if (protobuf != nullptr) {
            molch__protobuf__encrypted_backup__free_unpacked(protobuf, &protobuf_c_allocator);
        }
	}
};

static std::vector<unsigned char> decrypt_conversation_backup(
		const AutoFreeBuffer& backup,
		const BackupKeyArray& backup_key) {
	if (backup.empty()) {
		throw Exception("The backup was empty.");
	}

	//unpack the encrypted backup
	auto encrypted_backup{AutoFreeEncryptedBackup(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup.size(), backup.data()))};
	if (encrypted_backup.protobuf == nullptr) {
		throw Exception("Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup.protobuf->backup_version != 0) {
		throw Exception("Incompatible backup.");
	}
	if (!encrypted_backup.protobuf->has_backup_type || (encrypted_backup.protobuf->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
		throw Exception("Backup is not a conversation backup.");
	}
	if (!encrypted_backup.protobuf->has_encrypted_backup || (encrypted_backup.protobuf->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw Exception("The backup is missing the encrypted conversation state.");
	}
	if (!encrypted_backup.protobuf->has_encrypted_backup_nonce || (encrypted_backup.protobuf->encrypted_backup_nonce.len != 24)) {
		throw Exception("The backup is missing the nonce.");
	}

	std::vector<unsigned char> decrypted_backup(encrypted_backup.protobuf->encrypted_backup.len - crypto_secretbox_MACBYTES, 0);

	//decrypt the backup
	auto status{crypto_secretbox_open_easy(
			decrypted_backup.data(),
			encrypted_backup.protobuf->encrypted_backup.data,
			encrypted_backup.protobuf->encrypted_backup.len,
			encrypted_backup.protobuf->encrypted_backup_nonce.data,
			backup_key.data())};
	if (status != 0) {
		throw Exception("Failed to decrypt conversation backup.");
	}

	return decrypted_backup;
}

static std::vector<unsigned char> decrypt_full_backup(const AutoFreeBuffer& backup, const BackupKeyArray& backup_key) {
	//check input
	if (backup.empty()) {
		throw Exception("Backup was empty.");
	}

	//unpack the encrypted backup
	auto encrypted_backup{AutoFreeEncryptedBackup(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup.size(), backup.data()))};
	if (encrypted_backup.protobuf == nullptr) {
		throw Exception("Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup.protobuf->backup_version != 0) {
		throw Exception("Incompatible backup.");
	}
	if (!encrypted_backup.protobuf->has_backup_type || (encrypted_backup.protobuf->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
		throw Exception("Backup is not a conversation backup.");
	}
	if (!encrypted_backup.protobuf->has_encrypted_backup || (encrypted_backup.protobuf->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		throw Exception("The backup is missing the encrypted conversation state.");
	}
	if (!encrypted_backup.protobuf->has_encrypted_backup_nonce || (encrypted_backup.protobuf->encrypted_backup_nonce.len != 24)) {
		throw Exception("The backup is missing the nonce.");
	}

	std::vector<unsigned char> decrypted_backup(encrypted_backup.protobuf->encrypted_backup.len - crypto_secretbox_MACBYTES, 0);

	//decrypt the backup
	auto status{crypto_secretbox_open_easy(
			decrypted_backup.data(),
			encrypted_backup.protobuf->encrypted_backup.data,
			encrypted_backup.protobuf->encrypted_backup.len,
			encrypted_backup.protobuf->encrypted_backup_nonce.data,
			backup_key.data())};
	if (status != 0) {
		throw Exception("Failed to decrypt conversation backup.");
	}

	return decrypted_backup;
}

int main() {
	try {
	    if (sodium_init() != 0) {
	    	throw Exception("Failed to initialize libsodium.");
	    }

		//mustn't crash here!
		molch_destroy_all_users();

		BackupKeyArray backup_key;
		{
			auto status{molch_update_backup_key(backup_key.data(), backup_key.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to update backup key.");
			}
		}

		//check user count
		if (molch_user_count() != 0) {
			throw Exception("Wrong user count.");
		}

		//create a new user
		BackupKeyArray new_backup_key;
		PublicIdentity alice_public_identity;
		std::string alice_head_on_keyboard("mn ujkhuzn7b7bzh6ujg7j8hn");
		AutoFreeBuffer complete_export;
		AutoFreeBuffer alice_public_prekeys;
		{
			auto status{molch_create_user(
					alice_public_identity.data(),
					alice_public_identity.size(),
					&alice_public_prekeys.pointer,
					&alice_public_prekeys.length,
					new_backup_key.data(),
					new_backup_key.size(),
					&complete_export.pointer,
					&complete_export.length,
					char_to_uchar(alice_head_on_keyboard.data()),
					alice_head_on_keyboard.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to create Alice");
			}
		}

		if (backup_key == new_backup_key) {
			throw Exception("New backup key is the same as the old one.");
		}

		backup_key = new_backup_key;

		std::cout << "Alice public identity (" << alice_public_identity.size() << " Bytes):\n";
		std::cout << buffer_to_hex(alice_public_identity) << std::endl;
		if (complete_export.data() == nullptr) {
			throw Exception("Failed to export the librarys state after creating alice.");
		}


		//check user count
		if (molch_user_count() != 1) {
			throw Exception("Wrong user count.");
		}

		//create a new backup key
		{
			return_status status{molch_update_backup_key(backup_key.data(), backup_key.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to update backup key");
			}
		}

		std::cout << "Updated backup key:\n";
		std::cout << buffer_to_hex(backup_key) << std::endl;

		//create another user
		PublicIdentity bob_public_identity;
		std::string bob_head_on_keyboard("jnu8h77z6ht56ftgnujh");
		AutoFreeBuffer bob_public_prekeys;
		{
			auto status{molch_create_user(
					bob_public_identity.data(),
					bob_public_identity.size(),
					&bob_public_prekeys.pointer,
					&bob_public_prekeys.length,
					backup_key.data(),
					backup_key.size(),
					nullptr,
					nullptr,
					char_to_uchar(bob_head_on_keyboard.data()),
					bob_head_on_keyboard.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to create Bob.");
			}
		}

		std::cout << "Bob public identity (" << bob_public_identity.size() << " Bytes):\n";
		std::cout << buffer_to_hex(bob_public_identity) << std::endl;

		//check user count
		if (molch_user_count() != 2) {
			throw Exception("Wrong user count.");
		}

		//check user list
		size_t user_count{0};
		AutoFreeBuffer user_list;
		{
			auto status{molch_list_users(&user_list.pointer, &user_list.length, &user_count)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to list users");
			}
		}
		if ((user_count != 2) || (user_list.size() != user_count * 32)
				|| (memcmp(alice_public_identity.data(), user_list.data(), alice_public_identity.size()) != 0)
				|| (memcmp(bob_public_identity.data(), user_list.data() + 32, alice_public_identity.size()) != 0)) {
			throw Exception("User list is incorrect.");
		}

		//create a new send conversation (alice sends to bob)
		ConversationID alice_conversation;
		std::string alice_send_message("Hi Bob. Alice here!");
		AutoFreeBuffer alice_send_packet;
		{
			auto status{molch_start_send_conversation(
					alice_conversation.data(),
					alice_conversation.size(),
					&alice_send_packet.pointer,
					&alice_send_packet.length,
					alice_public_identity.data(),
					alice_public_identity.size(),
					bob_public_identity.data(),
					bob_public_identity.size(),
					bob_public_prekeys.data(),
					bob_public_prekeys.size(),
					char_to_uchar(alice_send_message.data()),
					alice_send_message.size(),
					nullptr,
					nullptr)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to start Alice' send conversation");
			}
		}

		//check conversation export
		size_t number_of_conversations{0};
		AutoFreeBuffer conversation_list;
		{
			auto status{molch_list_conversations(
					&conversation_list.pointer,
					&conversation_list.length,
					&number_of_conversations,
					alice_public_identity.data(),
					alice_public_identity.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to list conversations");
			}
		}
		if ((number_of_conversations != 1) || (memcmp(alice_conversation.data(), conversation_list.data(), sizeof(alice_conversation)) != 0)) {
			throw Exception("Failed to list conversations.");
		}

		//check the message type
		if (molch_get_message_type(alice_send_packet.data(), alice_send_packet.size()) != molch_message_type::PREKEY_MESSAGE) {
			throw Exception("Wrong message type.");
		}

		// export the prekeys again
		{
		    AutoFreeBuffer prekey_list;
			auto status{molch_get_prekey_list(
					&prekey_list.pointer,
					&prekey_list.length,
					alice_public_identity.data(),
					alice_public_identity.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to get prekey list.");
			}
		}

		//create a new receive conversation (bob receives from alice)
		ConversationID bob_conversation;
		AutoFreeBuffer bob_receive_message;
		AutoFreeBuffer bob_second_public_prekeys;
		{
			auto status{molch_start_receive_conversation(
					bob_conversation.data(),
					bob_conversation.size(),
					&bob_second_public_prekeys.pointer,
					&bob_second_public_prekeys.length,
					&bob_receive_message.pointer,
					&bob_receive_message.length,
					bob_public_identity.data(),
					bob_public_identity.size(),
					alice_public_identity.data(),
					alice_public_identity.size(),
					alice_send_packet.data(),
					alice_send_packet.size(),
					nullptr,
					nullptr)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to start Bob's receive conversation.");
			}
		}

		//compare sent and received messages
		std::cout << "sent (Alice): " << alice_send_message << '\n';
		std::cout << "received (Bob): " << std::string_view(uchar_to_char(bob_receive_message.data()), bob_receive_message.size()) << '\n';
		if ((alice_send_message.size() != bob_receive_message.size())
				|| (memcmp(alice_send_message.data(), bob_receive_message.data(), bob_receive_message.size()) != 0)) {
			throw Exception("Incorrect message received.");
		}

		//bob replies
		std::string bob_send_message{"Welcome Alice!"};
		AutoFreeBuffer conversation_export;
		AutoFreeBuffer bob_send_packet;
		{
			auto status{molch_encrypt_message(
					&bob_send_packet.pointer,
					&bob_send_packet.length,
					bob_conversation.data(),
					bob_conversation.size(),
					char_to_uchar(bob_send_message.data()),
					bob_send_message.size(),
					&conversation_export.pointer,
					&conversation_export.length)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to encypt Bob's send message.");
			}
		}

		if (conversation_export.pointer == nullptr) {
			throw Exception("Failed to export the conversation after encrypting a message.");
		}

		//check the message type
		if (molch_get_message_type(bob_send_packet.data(), bob_send_packet.size()) != molch_message_type::NORMAL_MESSAGE) {
			throw Exception("Wrong message type.");
		}

		//alice receives reply
		uint32_t alice_receive_message_number{UINT32_MAX};
		uint32_t alice_previous_receive_message_number{UINT32_MAX};
		AutoFreeBuffer alice_receive_message;
		{
			auto status{molch_decrypt_message(
					&alice_receive_message.pointer,
					&alice_receive_message.length,
					&alice_receive_message_number,
					&alice_previous_receive_message_number,
					alice_conversation.data(),
					alice_conversation.size(),
					bob_send_packet.data(),
					bob_send_packet.size(),
					nullptr,
					nullptr)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to decrypt Bob's message.");
			}
		}

		if ((alice_receive_message_number != 0) || (alice_previous_receive_message_number != 0)) {
			throw Exception("Incorrect receive message number for Alice.");
		}

		//compare sent and received messages
		std::cout << "sent (Bob): " << bob_send_message << '\n';
		std::cout << "received (Alice): " << std::string_view(uchar_to_char(alice_receive_message.data()), alice_receive_message.size()) << '\n';
		if ((bob_send_message.size() != alice_receive_message.size())
				|| (memcmp(bob_send_message.data(), alice_receive_message.data(), alice_receive_message.size()) != 0)) {
			throw Exception("Incorrect message received.");
		}

		//test export
		std::cout << "Test export!\n";
		AutoFreeBuffer backup;
		{
			auto status{molch_export(&backup.pointer, &backup.length)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to export backup.");
			}
		}

		//test import
		std::cout << "Test import!\n";
		{
			auto status{molch_import(
					new_backup_key.data(),
					new_backup_key.size(),
					backup.data(),
					backup.size(),
					backup_key.data(),
					backup_key.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to import backup.");
			}
		}

		auto decrypted_backup{decrypt_full_backup(backup, backup_key)};

		//compare the keys
		if (backup_key == new_backup_key) {
			throw Exception("New backup key expected.");
		}

		//copy the backup key
		backup_key = new_backup_key;

		//now export again
		AutoFreeBuffer imported_backup;
		{
			auto status{molch_export(&imported_backup.pointer, &imported_backup.length)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to export imported backup.");
			}
		}

		auto decrypted_imported_backup{decrypt_full_backup(imported_backup, backup_key)};

		//compare
		if (decrypted_backup != decrypted_imported_backup) {
			throw Exception("Imported backup is incorrect.");
		}

		//test conversation export
		AutoFreeBuffer second_backup;
		{
			auto status{molch_conversation_export(
					&second_backup.pointer,
					&second_backup.length,
					alice_conversation.data(),
					alice_conversation.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to export Alice's conversation.");
			}
		}

		std::cout << "Alice' conversation exported!\n";

		//import again
		{
			auto status{molch_conversation_import(
					new_backup_key.data(),
					new_backup_key.size(),
					second_backup.data(),
					second_backup.size(),
					backup_key.data(),
					backup_key.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to import conversation.");
			}
		}

		auto decrypted_conversation_backup{decrypt_conversation_backup(second_backup, backup_key)};

		//copy the backup key
		backup_key = new_backup_key;


		//export again
		AutoFreeBuffer second_imported_backup;
		{
			auto status{molch_conversation_export(
					&second_imported_backup.pointer,
					&second_imported_backup.length,
					alice_conversation.data(),
					alice_conversation.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to export Alice's conversation.");
			}
		}

		auto decrypted_imported_conversation_backup{decrypt_conversation_backup(second_imported_backup, backup_key)};

		//compare
		if (decrypted_conversation_backup != decrypted_imported_conversation_backup) {
			throw Exception("Protobuf of imported conversation is incorrect.");
		}

		//destroy the conversations
		{
			auto status{molch_end_conversation(alice_conversation.data(), alice_conversation.size(), nullptr, nullptr)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to end Alice's conversation.");
			}
		}
		{
			auto status{molch_end_conversation(bob_conversation.data(), bob_conversation.size(), nullptr, nullptr)};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to end Bob's conversation.");
			}
		}

		//check if conversation has ended
		number_of_conversations = 0;
		AutoFreeBuffer second_conversation_list;
		{
			auto status{molch_list_conversations(
					&second_conversation_list.pointer,
					&second_conversation_list.length,
					&number_of_conversations,
					alice_public_identity.data(),
					alice_public_identity.size())};
			if (status.status != status_type::SUCCESS) {
				throw Exception("Failed to list conversations.");
			}
		}
		if ((number_of_conversations != 0) || (second_conversation_list.pointer != nullptr)) {
			throw Exception("Failed to end conversation.");
		}
		std::cout << "Alice' conversation has ended successfully.\n";

		//destroy the users again
		molch_destroy_all_users();

		//check user count
		if (molch_user_count() != 0) {
			throw Exception("Wrong user count.");
		}

		//TODO check detection of invalid prekey list signatures and old timestamps + more scenarios

		std::string success_buffer("SUCCESS");
		AutoFreeBuffer printed_status;
		printed_status.pointer = char_to_uchar(molch_print_status(&printed_status.length, {status_type::SUCCESS, nullptr}));
		if ((printed_status.size() != (success_buffer.size() + sizeof('\0'))) || (memcmp(printed_status.data(), success_buffer.data(), std::size(success_buffer)) != 0)) {
			throw Exception("molch_print_status produces incorrect output.");
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
