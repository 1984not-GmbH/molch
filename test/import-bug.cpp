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
#include <iostream>

#include "utils.hpp"
#include "../lib/molch.h"
#include "../lib/user-store.hpp" //for PREKEY_AMOUNT
#include "../lib/zeroed_malloc.hpp"
#include "../lib/destroyers.hpp"

extern "C" {
	#include <encrypted_backup.pb-c.h>
}

static return_status decrypt_full_backup(
		//output
		Buffer ** decrypted_backup,
		//inputs
		const unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * backup_key,
		const size_t backup_key_length) noexcept {
	return_status status = return_status_init();

	EncryptedBackup *encrypted_backup_struct = nullptr;

	//check input
	if ((decrypted_backup == nullptr) || (backup == nullptr) || (backup_key == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to molch_import.");
	}
	if (backup_key_length != BACKUP_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "Backup key has an incorrect length.");
	}

	//unpack the encrypted backup
	encrypted_backup_struct = encrypted_backup__unpack(&protobuf_c_allocators, backup_length, backup);
	if (encrypted_backup_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
	}

	//check the backup
	if (encrypted_backup_struct->backup_version != 0) {
		THROW(INCORRECT_DATA, "Incompatible backup.");
	}
	if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
		THROW(INCORRECT_DATA, "Backup is not a conversation backup.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state.");
	}
	if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
		THROW(PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
	}

	*decrypted_backup = Buffer::createWithCustomAllocator(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES, zeroed_malloc, zeroed_free);
	THROW_on_failed_alloc(*decrypted_backup);

	//decrypt the backup
	{
		int status_int = crypto_secretbox_open_easy(
				(*decrypted_backup)->content,
				encrypted_backup_struct->encrypted_backup.data,
				encrypted_backup_struct->encrypted_backup.len,
				encrypted_backup_struct->encrypted_backup_nonce.data,
				backup_key);
		if (status_int != 0) {
			THROW(DECRYPT_ERROR, "Failed to decrypt conversation backup.");
		}
	}

cleanup:
	if (encrypted_backup_struct != nullptr) {
		encrypted_backup__free_unpacked(encrypted_backup_struct, &protobuf_c_allocators);
		encrypted_backup_struct = nullptr;
	}
	//decrypted_backup gets freed in main

	return status;
}

int main(void) noexcept {
	if (sodium_init() == -1) {
		return -1;
	}

	//mustn't crash here!
	molch_destroy_all_users();

	return_status status = return_status_init();
	Buffer alice_send_message("Hi Bob. Alice here!");

	//backup key buffer
	Buffer backup_key(BACKUP_KEY_SIZE, BACKUP_KEY_SIZE);
	Buffer new_backup_key(BACKUP_KEY_SIZE, BACKUP_KEY_SIZE);

	//create conversation buffers
	Buffer alice_conversation(CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	Buffer bob_conversation(CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);

	//alice key buffers
	Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	unsigned char *alice_public_prekeys = nullptr;
	size_t alice_public_prekeys_length = 0;

	//bobs key buffers
	Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	unsigned char *bob_public_prekeys = nullptr;
	size_t bob_public_prekeys_length = 0;

	//packet pointers
	unsigned char * alice_send_packet = nullptr;
	unsigned char * bob_send_packet = nullptr;

	unsigned char *printed_status = nullptr;

	// backups
	unsigned char *backup = nullptr;
	unsigned char *imported_backup = nullptr;

	// decrypted backups
	Buffer *decrypted_backup = nullptr;
	Buffer *decrypted_imported_backup = nullptr;
	Buffer *decrypted_conversation_backup = nullptr;
	Buffer *decrypted_imported_conversation_backup = nullptr;

	throw_on_invalid_buffer(backup_key);
	throw_on_invalid_buffer(new_backup_key);
	throw_on_invalid_buffer(alice_conversation);
	throw_on_invalid_buffer(bob_conversation);
	throw_on_invalid_buffer(alice_public_identity);
	throw_on_invalid_buffer(bob_public_identity);

	status = molch_update_backup_key(backup_key.content, backup_key.content_length);
	THROW_on_error(KEYGENERATION_FAILED, "Failed to update backup key.");

	//create a new user
	status = molch_create_user(
			alice_public_identity.content,
			alice_public_identity.content_length,
			&alice_public_prekeys,
			&alice_public_prekeys_length,
			backup_key.content,
			backup_key.content_length,
			nullptr,
			nullptr,
			nullptr,
			0);
	THROW_on_error(status.status, "Failed to create Alice!");

	printf("Alice public identity (%zu Bytes):\n", alice_public_identity.content_length);
	std::cout << alice_public_identity.toHex();

	//create another user
	status = molch_create_user(
			bob_public_identity.content,
			bob_public_identity.content_length,
			&bob_public_prekeys,
			&bob_public_prekeys_length,
			backup_key.content,
			backup_key.content_length,
			nullptr,
			nullptr,
			nullptr,
			0);
	THROW_on_error(status.status, "Failed to create Bob!");

	printf("Bob public identity (%zu Bytes):\n", bob_public_identity.content_length);
	std::cout << bob_public_identity.toHex();
	putchar('\n');

	//create a new send conversation (alice sends to bob)
	size_t alice_send_packet_length;
	status = molch_start_send_conversation(
			alice_conversation.content,
			alice_conversation.content_length,
			&alice_send_packet,
			&alice_send_packet_length,
			alice_public_identity.content,
			alice_public_identity.content_length,
			bob_public_identity.content,
			bob_public_identity.content_length,
			bob_public_prekeys,
			bob_public_prekeys_length,
			alice_send_message.content,
			alice_send_message.content_length,
			nullptr,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to start send conversation.");

	//create a new receive conversation (bob receives from alice)
	unsigned char *bob_receive_message;
	size_t bob_receive_message_length;
	status = molch_start_receive_conversation(
			bob_conversation.content,
			bob_conversation.content_length,
			&bob_public_prekeys,
			&bob_public_prekeys_length,
			&bob_receive_message,
			&bob_receive_message_length,
			bob_public_identity.content,
			bob_public_identity.content_length,
			alice_public_identity.content,
			alice_public_identity.content_length,
			alice_send_packet,
			alice_send_packet_length,
			nullptr,
			nullptr);
	THROW_on_error(CREATION_ERROR, "Failed to start receive conversation.");

	//test export
	printf("Test export!\n");
	size_t backup_length;
	status = molch_export(&backup, &backup_length);
	THROW_on_error(EXPORT_ERROR, "Failed to export.");

	//test import
	printf("Test import!\n");
	status = molch_import(
			new_backup_key.content,
			new_backup_key.content_length,
			backup,
			backup_length,
			backup_key.content,
			backup_key.content_length);
	on_error {
		THROW(IMPORT_ERROR, "Failed to import backup.");
	}

	status = decrypt_full_backup(&decrypted_backup, backup, backup_length, backup_key.content, backup_key.content_length);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt backup.");

	//copy the backup key
	if (backup_key.cloneFrom(&new_backup_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy backup key.");
	}

	//now export again
	size_t imported_backup_length;
	status = molch_export(&imported_backup, &imported_backup_length);
	on_error {
		THROW(EXPORT_ERROR, "Failed to export imported backup.");
	}

	status = decrypt_full_backup(&decrypted_imported_backup, imported_backup, imported_backup_length, backup_key.content, backup_key.content_length);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt imported backup.");

	//compare
	if (*decrypted_backup != *decrypted_imported_backup) {
		THROW(IMPORT_ERROR, "Imported backup is incorrect.");
	}

cleanup:
	free_and_null_if_valid(alice_public_prekeys);
	free_and_null_if_valid(bob_public_prekeys);
	free_and_null_if_valid(alice_send_packet);
	free_and_null_if_valid(bob_send_packet);
	free_and_null_if_valid(printed_status);
	free_and_null_if_valid(backup);
	free_and_null_if_valid(imported_backup);

	buffer_destroy_and_null_if_valid(decrypted_backup);
	buffer_destroy_and_null_if_valid(decrypted_imported_backup);
	buffer_destroy_and_null_if_valid(decrypted_conversation_backup);
	buffer_destroy_and_null_if_valid(decrypted_imported_conversation_backup);

	molch_destroy_all_users();

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
