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

/*
 * WARNING: ALTHOUGH THIS IMPLEMENTS THE AXOLOTL PROTOCOL, IT ISN't CONSIDERED SECURE ENOUGH TO USE AT THIS POINT
 */

#include <cstdint>
#include <memory>
#include <iterator>

#include "constants.h"
#include "../include/molch.h"
#include "packet.hpp"
#include "buffer.hpp"
#include "user-store.hpp"
#include "endianness.hpp"
#include "destroyers.hpp"
#include "malloc.hpp"
#include "protobuf.hpp"
#include "protobuf-arena.hpp"
#include "key.hpp"
#include "gsl.hpp"

using namespace Molch;

//global user store
static UserStore users;
static std::unique_ptr<BackupKey,SodiumDeleter<BackupKey>> global_backup_key;

class GlobalBackupKeyUnlocker {
public:
	GlobalBackupKeyUnlocker() {
		if (!global_backup_key) {
			throw Exception{status_type::GENERIC_ERROR, "No backup key to unlock!"};
		}
		Molch::sodium_mprotect_readonly(global_backup_key.get());
	}

	GlobalBackupKeyUnlocker(const GlobalBackupKeyUnlocker&) = default;
	GlobalBackupKeyUnlocker(GlobalBackupKeyUnlocker&&) = default;
	GlobalBackupKeyUnlocker& operator=(const GlobalBackupKeyUnlocker&) = default;
	GlobalBackupKeyUnlocker& operator=(GlobalBackupKeyUnlocker&&) = default;

	~GlobalBackupKeyUnlocker() noexcept {
		Molch::sodium_mprotect_noaccess(global_backup_key.get());
	}
};

class GlobalBackupKeyWriteUnlocker {
public:
	GlobalBackupKeyWriteUnlocker() {
		if (!global_backup_key) {
			throw Exception{status_type::GENERIC_ERROR, "No backup key to unlock!"};
		}
		Molch::sodium_mprotect_readwrite(global_backup_key.get());
	}

	GlobalBackupKeyWriteUnlocker(const GlobalBackupKeyWriteUnlocker&) = default;
	GlobalBackupKeyWriteUnlocker(GlobalBackupKeyWriteUnlocker&&) = default;
	GlobalBackupKeyWriteUnlocker& operator=(const GlobalBackupKeyWriteUnlocker&) = default;
	GlobalBackupKeyWriteUnlocker& operator=(GlobalBackupKeyWriteUnlocker&&) = default;

	~GlobalBackupKeyWriteUnlocker() noexcept {
		Molch::sodium_mprotect_noaccess(global_backup_key.get());
	}
};

/*
 * Create a prekey list.
 */
static result<MallocBuffer> create_prekey_list(const PublicSigningKey& public_signing_key) {
	//get the user
	auto user{users.find(public_signing_key)};
	if (user == nullptr) {
		throw Exception{status_type::NOT_FOUND, "Couldn't find the user to create a prekey list from."};
	}

	//rotate the prekeys
	OUTCOME_TRY(user->prekeys.rotate());

	//copy the public identity to the prekey list
	MallocBuffer unsigned_prekey_list{
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t),
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t)};
	OUTCOME_TRY(unsigned_prekey_list.copyFromRaw(0, user->masterKeys().getIdentityKey().data(), 0, PUBLIC_KEY_SIZE));

	//get the prekeys
	OUTCOME_TRY(prekey_list_buffer, user->prekeys.list());
	OUTCOME_TRY(copyFromTo(prekey_list_buffer, {&unsigned_prekey_list[PUBLIC_KEY_SIZE], PREKEY_AMOUNT * PUBLIC_KEY_SIZE}));

	//add the expiration date
	int64_t expiration_date{now().count() + seconds{3_months}.count()};
	span<std::byte> big_endian_expiration_date{&unsigned_prekey_list[PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE], sizeof(int64_t)};
	OUTCOME_TRY(to_big_endian(expiration_date, big_endian_expiration_date));

	//sign the prekey list with the current identity key
	MallocBuffer prekey_list{
			unsigned_prekey_list.size() + SIGNATURE_SIZE,
			unsigned_prekey_list.size() + SIGNATURE_SIZE};
	OUTCOME_TRY(signed_data, user->masterKeys().sign(unsigned_prekey_list));
	OUTCOME_TRY(copyFromTo(signed_data, prekey_list));

	return prekey_list;
}

	static result<void> update_backup_key(unsigned char * const new_key, const size_t new_key_length) {
		if ((new_key == nullptr) or (new_key_length != BACKUP_KEY_SIZE)) {
			return Error(status_type::INVALID_VALUE, "The new key is null or doesn't have the correct size.");
		}

		OUTCOME_TRY(Molch::sodium_init());

		// create a backup key buffer if it doesnt exist already
		if (global_backup_key == nullptr) {
			global_backup_key = std::unique_ptr<BackupKey,SodiumDeleter<BackupKey>>(sodium_malloc<BackupKey>(1));
			new (global_backup_key.get()) BackupKey();
		}

		//make the content of the backup key writable
		GlobalBackupKeyWriteUnlocker unlocker;

		randombytes_buf(*global_backup_key);
		return copyFromTo(*global_backup_key, {uchar_to_byte(new_key), new_key_length});
	}

MOLCH_PUBLIC(return_status) molch_create_user(
		//outputs
		unsigned char *const public_master_key, //PUBLIC_MASTER_KEY_SIZE
		const size_t public_master_key_length,
		unsigned char **const prekey_list, //needs to be freed
		size_t *const prekey_list_length,
		unsigned char * backup_key, //BACKUP_KEY_SIZE
		const size_t backup_key_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length,
		//optional input (can be nullptr)
		const unsigned char *const random_data,
		const size_t random_data_length) {
	try {
		Expects((public_master_key != nullptr)
			&& (prekey_list != nullptr)
			&& (prekey_list_length != nullptr)
			&& (backup_key_length == BACKUP_KEY_SIZE)
			&& (public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

		TRY_VOID(Molch::sodium_init());

		//create a new backup key
		TRY_VOID(update_backup_key(backup_key, backup_key_length));

		//create the user
		PublicSigningKey public_master_key_key;
		if (random_data_length != 0) {
			TRY_WITH_RESULT(user_result, Molch::User::create({{uchar_to_byte(random_data), random_data_length}}));
			auto& user{user_result.value()};
			public_master_key_key = user.id();
			users.add(std::move(user));
		} else {
			TRY_WITH_RESULT(user_result, Molch::User::create());
			auto& user{user_result.value()};
			public_master_key_key = user.id();
			users.add(std::move(user));
		}
		TRY_VOID(copyFromTo(public_master_key_key, {uchar_to_byte(public_master_key), public_master_key_length}));

		TRY_WITH_RESULT(prekey_list_buffer_result, create_prekey_list(public_master_key_key));
		auto& prekey_list_buffer{prekey_list_buffer_result.value()};

		if (backup != nullptr) {
			*backup = nullptr;
			if (backup_length != nullptr) {
				return_status status = molch_export(backup, backup_length);
				on_error {
					throw Exception{status};
				}
			}
		}

		//move the prekey list out of the buffer
		*prekey_list_length = prekey_list_buffer.size();
		*prekey_list = byte_to_uchar(prekey_list_buffer.release());
	} catch (const Exception& exception) {
		return exception.toReturnStatus();
	} catch (const std::exception& exception) {
		return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
	}

	return success_status;
}

MOLCH_PUBLIC(return_status) molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	try {
		if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "Public master key has incorrect size."};
		}

		TRY_WITH_RESULT(public_master_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(public_master_key), PUBLIC_MASTER_KEY_SIZE}));
		const auto& public_master_key_key{public_master_key_key_result.value()};
		users.remove(public_master_key_key);

		if (backup != nullptr) {
			*backup = nullptr;
			if (backup_length != nullptr) {
				auto status{molch_export(backup, backup_length)};
				on_error {
					throw Exception{status};
				}
			}
		}
	} catch (const Exception& exception) {
		return exception.toReturnStatus();
	} catch (const std::exception& exception) {
		return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
	}

	return success_status;
}

MOLCH_PUBLIC(size_t) molch_user_count() {
	return users.size();
}

MOLCH_PUBLIC(void) molch_destroy_all_users() {
	users.clear();
}

MOLCH_PUBLIC(return_status) molch_list_users(
		unsigned char **const user_list,
		size_t * const user_list_length, //length in bytes
		size_t * const count) {
	auto status{success_status};

	try {
		Expects(user_list_length != nullptr);

		//get the list of users and copy it
		TRY_WITH_RESULT(list_result, users.list());
		const auto& list{list_result.value()};

		*count = molch_user_count();

		if (*count == 0) {
			*user_list = nullptr;
		} else {
			*user_list = throwing_malloc<unsigned char>(*count * PUBLIC_MASTER_KEY_SIZE);
			std::copy(std::cbegin(list), std::cend(list), uchar_to_byte(*user_list));
		}

		*user_list_length = list.size();
	} catch (const Exception& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		status = Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		goto cleanup;
	}

cleanup:
	on_error {
		if (user_list != nullptr) {
			free_and_null_if_valid(*user_list);
		}

		*count = 0;
	}

	return status;
}

MOLCH_PUBLIC(molch_message_type) molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length) {
	const auto unverified_metadata_result = packet_get_metadata_without_verification({uchar_to_byte(packet), packet_length});
	if (not unverified_metadata_result.has_value()) {
		return molch_message_type::INVALID;
	}

	const auto& unverified_metadata{unverified_metadata_result.value()};

	return unverified_metadata.packet_type;
}

/*
 * Verify prekey list and extract the public identity
 * and choose a prekey.
 */
static result<PublicKey> verify_prekey_list(
		const span<const std::byte> prekey_list,
		const PublicSigningKey& public_signing_key) {
	//verify the signature
	Buffer verified_prekey_list{prekey_list.size() - SIGNATURE_SIZE, prekey_list.size() - SIGNATURE_SIZE};
	OUTCOME_TRY(crypto_sign_open(
			verified_prekey_list,
			prekey_list,
			public_signing_key));

	//get the expiration date
	int64_t expiration_date{0};
	span<std::byte> big_endian_expiration_date{&verified_prekey_list[PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE], sizeof(int64_t)};
	OUTCOME_TRY(from_big_endian(expiration_date, big_endian_expiration_date));

	//make sure the prekey list isn't too old
	int64_t current_time{now().count()};
	if (expiration_date < current_time) {
		return Error(status_type::OUTDATED, "Prekey list has expired (older than 3 months).");
	}

	//copy the public identity key
	PublicKey public_identity_key;
	OUTCOME_TRY(copyFromTo(verified_prekey_list, {public_identity_key.data(), PUBLIC_KEY_SIZE}, PUBLIC_KEY_SIZE));

	return public_identity_key;
}

MOLCH_PUBLIC(return_status) molch_start_send_conversation(
		//outputs
		unsigned char *const conversation_id, //CONVERSATION_ID_SIZE long (from conversation.h)
		const size_t conversation_id_length,
		unsigned char **const packet, //free after use
		size_t *packet_length,
		//inputs
		const unsigned char *const sender_public_master_key, //signing key of the sender (user)
		const size_t sender_public_master_key_length,
		const unsigned char *const receiver_public_master_key, //signing key of the receiver
		const size_t receiver_public_master_key_length,
		const unsigned char *const prekey_list, //prekey list of the receiver
		const size_t prekey_list_length,
		const unsigned char *const message,
		const size_t message_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	try {
		Expects((conversation_id != nullptr)
				&& (packet != nullptr)
				&& (packet_length != nullptr)
				&& (prekey_list != nullptr)
				&& (sender_public_master_key != nullptr)
				&& (receiver_public_master_key != nullptr)
				&& (conversation_id_length == CONVERSATION_ID_SIZE)
				&& (sender_public_master_key_length == PUBLIC_MASTER_KEY_SIZE)
				&& (receiver_public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

		//get the user that matches the public signing key of the sender
		TRY_WITH_RESULT(sender_public_master_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(sender_public_master_key), PUBLIC_MASTER_KEY_SIZE}));
		const auto& sender_public_master_key_key{sender_public_master_key_key_result.value()};
		auto user{users.find(sender_public_master_key_key)};
		if (user == nullptr) {
			throw Exception{status_type::NOT_FOUND, "User not found."};
		}

		//get the receivers public ephemeral and identity
		TRY_WITH_RESULT(receiver_public_master_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(receiver_public_master_key), PUBLIC_MASTER_KEY_SIZE}));
		const auto& receiver_public_master_key_key{receiver_public_master_key_key_result.value()};
		TRY_WITH_RESULT(receiver_public_identity_result, verify_prekey_list(
				{uchar_to_byte(prekey_list), prekey_list_length},
				receiver_public_master_key_key));
		const auto& receiver_public_identity{receiver_public_identity_result.value()};

		//unlock the master keys
		MasterKeys::Unlocker unlocker{user->masterKeys()};

		//create the conversation and encrypt the message
		span<const std::byte> prekeys{uchar_to_byte(prekey_list) + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t)};
		TRY_WITH_RESULT(private_identity_key, user->masterKeys().getPrivateIdentityKey());
		TRY_WITH_RESULT(send_conversation_result, Molch::Conversation::createSendConversation(
			{uchar_to_byte(message), message_length},
			user->masterKeys().getIdentityKey(),
			*private_identity_key.value(),
			receiver_public_identity,
			prekeys));
		auto& send_conversation{send_conversation_result.value()};

		//copy the conversation id
		TRY_VOID(copyFromTo(send_conversation.conversation.id(), {uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE}));

		user->conversations.add(std::move(send_conversation.conversation));

		//copy the packet to a malloced buffer output
		MallocBuffer malloced_packet{send_conversation.packet.size(), 0};
		TRY_VOID(malloced_packet.cloneFrom(send_conversation.packet));

		if (backup != nullptr) {
			*backup = nullptr;
			if (backup_length != nullptr) {
				auto status{molch_export(backup, backup_length)};
				on_error {
					throw Exception{status};
				}
			}
		}

		*packet_length = malloced_packet.size();
		*packet = byte_to_uchar(malloced_packet.release());
	} catch (const Exception& exception) {
		return exception.toReturnStatus();
	} catch (const std::exception& exception) {
		return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
	}

	return success_status;
}

	MOLCH_PUBLIC(return_status) molch_start_receive_conversation(
			//outputs
			unsigned char * const conversation_id, //CONVERSATION_ID_SIZE long (from conversation.h)
			const size_t conversation_id_length,
			unsigned char ** const prekey_list, //free after use
			size_t * const prekey_list_length,
			unsigned char ** const message, //free after use
			size_t * const message_length,
			//inputs
			const unsigned char * const receiver_public_master_key, //signing key of the receiver (user)
			const size_t receiver_public_master_key_length,
			const unsigned char * const sender_public_master_key, //signing key of the sender
			const size_t sender_public_master_key_length,
			const unsigned char * const packet, //received prekey packet
			const size_t packet_length,
			//optional output (can be nullptr)
			unsigned char ** const backup, //exports the entire library state, free after use, check if nullptr before use!
			size_t * const backup_length
			) {
		try {
			Expects((conversation_id != nullptr)
				&& (message != nullptr) && (message_length != nullptr)
				&& (packet != nullptr)
				&& (prekey_list != nullptr) && (prekey_list_length != nullptr)
				&& (sender_public_master_key != nullptr)
				&& (receiver_public_master_key != nullptr)
				&& (conversation_id_length == CONVERSATION_ID_SIZE)
				&& (sender_public_master_key_length == PUBLIC_MASTER_KEY_SIZE)
				&& (receiver_public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

			//get the user that matches the public signing key of the receiver
			TRY_WITH_RESULT(receiver_public_master_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(receiver_public_master_key), PUBLIC_MASTER_KEY_SIZE}));
			const auto& receiver_public_master_key_key{receiver_public_master_key_key_result.value()};
			auto user{users.find(receiver_public_master_key_key)};
			if (user == nullptr) {
				throw Exception{status_type::NOT_FOUND, "User not found in the user store."};
			}

			//unlock the master keys
			MasterKeys::Unlocker unlocker{user->masterKeys()};

			//create the conversation
			TRY_WITH_RESULT(private_identity_key, user->masterKeys().getPrivateIdentityKey());
			TRY_WITH_RESULT(receive_conversation_result, Molch::Conversation::createReceiveConversation(
				{uchar_to_byte(packet), packet_length},
				user->masterKeys().getIdentityKey(),
				*private_identity_key.value(),
				user->prekeys));
			auto& receive_conversation{receive_conversation_result.value()};

			//copy the conversation id
			TRY_VOID(copyFromTo(receive_conversation.conversation.id(), {uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE}));

			//create the prekey list
			TRY_WITH_RESULT(prekey_list_buffer_result, create_prekey_list(receiver_public_master_key_key));
			auto& prekey_list_buffer{prekey_list_buffer_result.value()};

			//add the conversation to the conversation store
			user->conversations.add(std::move(receive_conversation.conversation));

			//copy the message
			MallocBuffer malloced_message{receive_conversation.message.size(), 0};
			TRY_VOID(malloced_message.cloneFrom(receive_conversation.message));

			if (backup != nullptr) {
				*backup = nullptr;
				if (backup_length != nullptr) {
					auto status{molch_export(backup, backup_length)};
					on_error {
						throw Exception{status};
					}
				}
			}

			*message_length = malloced_message.size();
			*message = byte_to_uchar(malloced_message.release());

			*prekey_list_length = prekey_list_buffer.size();
			*prekey_list = byte_to_uchar(prekey_list_buffer.release());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	static result<MallocBuffer> export_conversation(const span<const std::byte> conversation_id) {
		ProtobufCEncryptedBackup encrypted_backup_struct;
		molch__protobuf__encrypted_backup__init(&encrypted_backup_struct);

		if ((global_backup_key == nullptr) || (global_backup_key->size() != BACKUP_KEY_SIZE)) {
			return Error(status_type::INCORRECT_DATA, "No backup key found.");
		}

		//find the conversation
		Molch::User *user{nullptr};
		OUTCOME_TRY(conversation_id_key, ConversationId::fromSpan(conversation_id));
		auto conversation{users.findConversation(user, conversation_id_key)};
		if (conversation == nullptr) {
			throw Exception{status_type::NOT_FOUND, "Failed to find the conversation."};
		}

		//export the conversation
		Arena arena;
		OUTCOME_TRY(conversation_struct, conversation->exportProtobuf(arena));

		//pack the struct
		auto conversation_size{molch__protobuf__conversation__get_packed_size(conversation_struct)};
		auto conversation_buffer_content{arena.allocate<std::byte>(conversation_size)};
		span<std::byte> conversation_buffer{conversation_buffer_content, conversation_size};
		molch__protobuf__conversation__pack(conversation_struct, byte_to_uchar(conversation_buffer.data()));

		//generate the nonce
		Buffer backup_nonce(BACKUP_NONCE_SIZE, BACKUP_NONCE_SIZE);
		randombytes_buf(backup_nonce);

		//allocate the output
		Buffer backup_buffer{conversation_size + crypto_secretbox_MACBYTES, conversation_size + crypto_secretbox_MACBYTES};

		//encrypt the backup
		GlobalBackupKeyUnlocker unlocker;
		auto status{crypto_secretbox_easy(
				byte_to_uchar(backup_buffer.data()),
				byte_to_uchar(conversation_buffer.data()),
				conversation_buffer.size(),
				byte_to_uchar(backup_nonce.data()),
				byte_to_uchar(global_backup_key->data()))};
		if (status != 0) {
			OUTCOME_TRY(backup_buffer.setSize(0));
			return Error(status_type::ENCRYPT_ERROR, "Failed to enrypt conversation state.");
		}

		//fill in the encrypted backup struct
		//metadata
		encrypted_backup_struct.backup_version = 0;
		encrypted_backup_struct.has_backup_type = true;
		encrypted_backup_struct.backup_type = MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP;
		//nonce
		encrypted_backup_struct.has_encrypted_backup_nonce = true;
		encrypted_backup_struct.encrypted_backup_nonce.data = byte_to_uchar(backup_nonce.data());
		encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce.size();
		//encrypted backup
		encrypted_backup_struct.has_encrypted_backup = true;
		encrypted_backup_struct.encrypted_backup.data = byte_to_uchar(backup_buffer.data());
		encrypted_backup_struct.encrypted_backup.len = backup_buffer.size();

		//now pack the entire backup
		const auto encrypted_backup_size{molch__protobuf__encrypted_backup__get_packed_size(&encrypted_backup_struct)};
		MallocBuffer malloced_encrypted_backup{encrypted_backup_size, 0};
		OUTCOME_TRY(malloced_encrypted_backup.setSize(molch__protobuf__encrypted_backup__pack(&encrypted_backup_struct, byte_to_uchar(malloced_encrypted_backup.data()))));
		if (malloced_encrypted_backup.size() != encrypted_backup_size) {
			return Error(status_type::PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
		}

		return std::move(malloced_encrypted_backup);
	}

	MOLCH_PUBLIC(return_status) molch_encrypt_message(
			//output
			unsigned char ** const packet, //free after use
			size_t *packet_length,
			//inputs
			const unsigned char * const conversation_id,
			const size_t conversation_id_length,
			const unsigned char * const message,
			const size_t message_length,
			//optional output (can be nullptr)
			unsigned char ** const conversation_backup, //exports the conversation, free after use, check if nullptr before use!
			size_t * const conversation_backup_length
			) {
		try {
			Expects((packet != nullptr) and (packet_length != nullptr)
				and (message != nullptr)
				and (conversation_id != nullptr)
				and (conversation_id_length == CONVERSATION_ID_SIZE)
				and ((conversation_backup == nullptr) or (conversation_backup != nullptr)));

			//find the conversation
			TRY_WITH_RESULT(conversation_id_key_result, ConversationId::fromSpan({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE}));
			const auto& conversation_id_key{conversation_id_key_result.value()};
			Molch::User *user;
			auto conversation{users.findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Failed to find a conversation for the given ID."};
			}

			TRY_WITH_RESULT(packet_buffer_result, conversation->send({uchar_to_byte(message), message_length}, std::nullopt));
			auto& packet_buffer{packet_buffer_result.value()};

			//copy the packet content
			MallocBuffer malloced_packet{packet_buffer.size(), 0};
			TRY_VOID(malloced_packet.cloneFrom(packet_buffer));

			if (conversation_backup != nullptr) {
				*conversation_backup = nullptr;
				TRY_WITH_RESULT(exported_conversation_result, export_conversation(conversation->id()));
				auto& exported_conversation{exported_conversation_result.value()};
				*conversation_backup_length = exported_conversation.size();
				*conversation_backup = byte_to_uchar(exported_conversation.release());
			}

			*packet_length = malloced_packet.size();
			*packet = byte_to_uchar(malloced_packet.release());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_decrypt_message(
			//outputs
			unsigned char ** const message, //free after use
			size_t *message_length,
			uint32_t * const receive_message_number,
			uint32_t * const previous_receive_message_number,
			//inputs
			const unsigned char * const conversation_id,
			const size_t conversation_id_length,
			const unsigned char * const packet,
			const size_t packet_length,
			//optional output (can be nullptr)
			unsigned char ** const conversation_backup, //exports the conversation, free after use, check if nullptr before use!
			size_t * const conversation_backup_length
		) {
		try {
			Expects((message != nullptr)
					and (message_length != nullptr)
					and (packet != nullptr)
					and (conversation_id != nullptr)
					and (receive_message_number != nullptr)
					and (previous_receive_message_number != nullptr)
					and (conversation_id_length == CONVERSATION_ID_SIZE)
					and ((conversation_backup == nullptr) or (conversation_backup_length != nullptr)));

			//find the conversation
			TRY_WITH_RESULT(conversation_id_key_result, ConversationId::fromSpan({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE}));
			const auto& conversation_id_key{conversation_id_key_result.value()};
			Molch::User* user;
			auto conversation{users.findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Failed to find conversation with the given ID."};
			}

			TRY_WITH_RESULT(received_message_result, conversation->receive({uchar_to_byte(packet), packet_length}));
			auto& received_message{received_message_result.value()};
			*receive_message_number = received_message.message_number;
			*previous_receive_message_number = received_message.previous_message_number;

			//copy the message
			MallocBuffer malloced_message{received_message.message.size(), 0};
			TRY_VOID(malloced_message.cloneFrom(received_message.message));

			if (conversation_backup != nullptr) {
				*conversation_backup = nullptr;
				TRY_WITH_RESULT(exported_conversation_result, export_conversation(conversation_id_key));
				auto& exported_conversation{exported_conversation_result.value()};
				*conversation_backup_length = exported_conversation.size();
				*conversation_backup = byte_to_uchar(exported_conversation.release());
			}

			*message_length = malloced_message.size();
			*message = byte_to_uchar(malloced_message.release());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_end_conversation(
			//input
			const unsigned char * const conversation_id,
			const size_t conversation_id_length,
			//optional output (can be nullptr)
			unsigned char ** const backup,
			size_t * const backup_length
			) {
		try {
			Expects((conversation_id != nullptr)
					&& (conversation_id_length == CONVERSATION_ID_SIZE));

			//find the conversation
			Molch::User *user{nullptr};
			TRY_WITH_RESULT(conversation_id_key_result, ConversationId::fromSpan({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE}));
			const auto& conversation_id_key{conversation_id_key_result.value()};
			auto conversation{users.findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Couldn't find conversation."};
			}

			user->conversations.remove(conversation_id_key);

			if (backup != nullptr) {
				*backup = nullptr;
				if (backup_length != nullptr) {
					auto status{molch_export(backup, backup_length)};
					on_error {
						throw Exception{status};
					}
				}
			}
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_list_conversations(
			//outputs
			unsigned char ** const conversation_list,
			size_t * const conversation_list_length,
			size_t * const number,
			//inputs
			const unsigned char * const user_public_master_key,
			const size_t user_public_master_key_length) {
		auto status{success_status};

		try {
			if (conversation_list != nullptr) {
				*conversation_list = nullptr;
			}

			Expects((user_public_master_key != nullptr)
					&& (conversation_list != nullptr)
					&& (conversation_list_length != nullptr)
					&& (number != nullptr)
					&& (user_public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

			TRY_WITH_RESULT(user_public_master_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(user_public_master_key), PUBLIC_MASTER_KEY_SIZE}));
			const auto& user_public_master_key_key{user_public_master_key_key_result.value()};
			auto user{users.find(user_public_master_key_key)};
			if (user == nullptr) {
				throw Exception{status_type::NOT_FOUND, "No user found for the given public identity."};
			}

			TRY_WITH_RESULT(conversation_list_buffer_result, user->conversations.list());
			const auto& conversation_list_buffer{conversation_list_buffer_result.value()};
			if (conversation_list_buffer.empty()) {
				// list is empty
				*conversation_list = nullptr;
				*number = 0;
			} else {
				if ((conversation_list_buffer.size() % CONVERSATION_ID_SIZE) != 0) {
					throw Exception{status_type::INCORRECT_BUFFER_SIZE, "The conversation ID buffer has an incorrect length."};
				}
				*number = conversation_list_buffer.size() / CONVERSATION_ID_SIZE;

				//allocate the conversation list output and copy it over
				MallocBuffer malloced_conversation_list{conversation_list_buffer.size(), 0};
				TRY_VOID(malloced_conversation_list.cloneFrom(conversation_list_buffer));
				*conversation_list_length = malloced_conversation_list.size();
				*conversation_list = byte_to_uchar(malloced_conversation_list.release());
			}
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			status = Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
			goto cleanup;
		}

	cleanup:
		on_error {
			if (number != nullptr) {
				*number = 0;
			}

			if (conversation_list_length != nullptr) {
				*conversation_list_length = 0;
			}
		}

		return status;
	}

	MOLCH_PUBLIC(char*) molch_print_status(size_t * const output_length, return_status status) {
		if (output_length == nullptr) {
			return nullptr;
		}

		auto printed{return_status_print(status)};
		*output_length = printed.size();
		return printed.data();
	}

	MOLCH_PUBLIC(const char*) molch_print_status_type(status_type type) {
		return return_status_get_name(type);
	}

	MOLCH_PUBLIC(void) molch_destroy_return_status(return_status * const status) {
		if (status == nullptr) {
			return;
		}
	}

	MOLCH_PUBLIC(return_status) molch_conversation_export(
			//output
			unsigned char ** const backup,
			size_t * const backup_length,
			//input
			const unsigned char * const conversation_id,
			const size_t conversation_id_length) {
		if ((backup == nullptr) or (backup_length == nullptr)
			or (conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)) {
			return {status_type::INVALID_VALUE, "One of the inputs to molch_conversation_export was NULL or of incorrect length."};
		}

		try {
			auto encrypted_backup_result{export_conversation({uchar_to_byte(conversation_id), conversation_id_length})};
			if (encrypted_backup_result.has_error()) {
				return encrypted_backup_result.error().toReturnStatus();
			}
			auto& encrypted_backup{encrypted_backup_result.value()};
			*backup_length = encrypted_backup.size();
			*backup = byte_to_uchar(encrypted_backup.release());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_conversation_import(
			//output
			unsigned char * new_backup_key,
			const size_t new_backup_key_length,
			//inputs
			const unsigned char * const backup,
			const size_t backup_length,
			const unsigned char * backup_key,
			const size_t backup_key_length) {
		try {
			Expects((backup != nullptr)
					&& (backup_key != nullptr)
					&& (backup_key_length == BACKUP_KEY_SIZE)
					&& (new_backup_key_length == BACKUP_KEY_SIZE));

			//unpack the encrypted backup
			auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup_length, backup))};
			if (encrypted_backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
			}

			//check the backup
			if (encrypted_backup_struct->backup_version != 0) {
				throw Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
			}
			if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
				throw Exception{status_type::INCORRECT_DATA, "Backup is not a conversation backup."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
			}

			Arena arena;
			auto decrypted_backup_content{arena.allocate<std::byte>(
						encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
			span<std::byte> decrypted_backup{
					decrypted_backup_content,
					encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES};

			//decrypt the backup
			auto status_int{crypto_secretbox_open_easy(
					byte_to_uchar(decrypted_backup.data()),
					encrypted_backup_struct->encrypted_backup.data,
					encrypted_backup_struct->encrypted_backup.len,
					encrypted_backup_struct->encrypted_backup_nonce.data,
					backup_key)};
			if (status_int != 0) {
				throw Exception{status_type::DECRYPT_ERROR, "Failed to decrypt conversation backup."};
			}

			//unpack the struct
			auto arena_protoc_allocator{arena.getProtobufCAllocator()};
			auto conversation_struct{molch__protobuf__conversation__unpack(&arena_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()))};
			if (conversation_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversations protobuf-c."};
			}

			//import the conversation
			ProtobufCConversation conversation_pointer{*conversation_struct};
			Molch::User* containing_user{nullptr};
			TRY_WITH_RESULT(conversation_id_key_result, ConversationId::fromSpan({conversation_struct->id}));
			const auto& conversation_id_key{conversation_id_key_result.value()};
			auto existing_conversation{users.findConversation(containing_user, conversation_id_key)};
			if (existing_conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Containing store not found."};
			}

			TRY_WITH_RESULT(conversation_result, Conversation::import(conversation_pointer));
			auto& conversation{conversation_result.value()};
			containing_user->conversations.add(std::move(conversation));

			TRY_VOID(update_backup_key(new_backup_key, new_backup_key_length));
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	static result<MallocBuffer> export_all() {
		GlobalBackupKeyUnlocker unlocker;
		if (global_backup_key == nullptr) {
			throw Exception{status_type::INCORRECT_DATA, "No backup key found."};
		}

		Arena arena;
		auto backup_struct{arena.allocate<ProtobufCBackup>(1)};
		molch__protobuf__backup__init(backup_struct);

		//export the conversation
		outcome_protobuf_array_arena_export(arena, backup_struct, users, users);

		//pack the struct
		auto backup_struct_size{molch__protobuf__backup__get_packed_size(backup_struct)};
		auto users_buffer_content{arena.allocate<std::byte>(backup_struct_size)};
		span<std::byte> users_buffer{users_buffer_content, backup_struct_size};
		molch__protobuf__backup__pack(backup_struct, byte_to_uchar(users_buffer.data()));

		//generate the nonce
		Buffer backup_nonce(BACKUP_NONCE_SIZE, BACKUP_NONCE_SIZE);
		randombytes_buf(backup_nonce);

		//allocate the output
		Buffer backup_buffer{backup_struct_size + crypto_secretbox_MACBYTES, backup_struct_size + crypto_secretbox_MACBYTES};

		//encrypt the backup
		auto status{crypto_secretbox_easy(
				byte_to_uchar(backup_buffer.data()),
				byte_to_uchar(users_buffer.data()),
				users_buffer.size(),
				byte_to_uchar(backup_nonce.data()),
				byte_to_uchar(global_backup_key->data()))};
		if (status != 0) {
			throw Exception{status_type::ENCRYPT_ERROR, "Failed to enrypt conversation state."};
		}

		//fill in the encrypted backup struct
		ProtobufCEncryptedBackup encrypted_backup_struct;
		molch__protobuf__encrypted_backup__init(&encrypted_backup_struct);
		//metadata
		encrypted_backup_struct.backup_version = 0;
		encrypted_backup_struct.has_backup_type = true;
		encrypted_backup_struct.backup_type = MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP;
		//nonce
		encrypted_backup_struct.has_encrypted_backup_nonce = true;
		encrypted_backup_struct.encrypted_backup_nonce.data = byte_to_uchar(backup_nonce.data());
		encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce.size();
		//encrypted backup
		encrypted_backup_struct.has_encrypted_backup = true;
		encrypted_backup_struct.encrypted_backup.data = byte_to_uchar(backup_buffer.data());
		encrypted_backup_struct.encrypted_backup.len = backup_buffer.size();

		//now pack the entire backup
		const auto encrypted_backup_size{molch__protobuf__encrypted_backup__get_packed_size(&encrypted_backup_struct)};
		MallocBuffer malloced_encrypted_backup{encrypted_backup_size, 0};
		OUTCOME_TRY(malloced_encrypted_backup.setSize(molch__protobuf__encrypted_backup__pack(&encrypted_backup_struct, byte_to_uchar(malloced_encrypted_backup.data()))));
		if (malloced_encrypted_backup.size() != encrypted_backup_size) {
			throw Exception{status_type::PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation."};
		}

		return malloced_encrypted_backup;
	}

	MOLCH_PUBLIC(return_status) molch_export(
			unsigned char ** const backup,
			size_t *backup_length) {
		if ((backup == nullptr) or (backup_length == nullptr)) {
			return Exception(status_type::INVALID_VALUE, "backup or backup_length are NULL").toReturnStatus();
		}

		try {
			auto exported_backup_result{export_all()};
			if (exported_backup_result.has_error()) {
				return Exception(exported_backup_result.error()).toReturnStatus();
			}
			auto& exported_backup{exported_backup_result.value()};
			//now pack the entire backup
			*backup_length = exported_backup.size();
			*backup = byte_to_uchar(exported_backup.release());
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_import(
			//output
			unsigned char * const new_backup_key, //BACKUP_KEY_SIZE, can be the same pointer as the backup key
			const size_t new_backup_key_length,
			//inputs
			unsigned char * const backup,
			const size_t backup_length,
			const unsigned char * const backup_key, //BACKUP_KEY_SIZE
			const size_t backup_key_length
			) {
		try {
			Expects((backup != nullptr)
					&& (backup_key != nullptr)
					&& (backup_key_length == BACKUP_KEY_SIZE)
					&& (new_backup_key_length == BACKUP_KEY_SIZE));

			TRY_VOID(Molch::sodium_init());

			//unpack the encrypted backup
			auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup_length, backup))};
			if (encrypted_backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
			}

			//check the backup
			if (encrypted_backup_struct->backup_version != 0) {
				throw Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
			}
			if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
				throw Exception{status_type::INCORRECT_DATA, "Backup is not a full backup."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted state."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
			}

			Arena arena;
			auto decrypted_backup_content{arena.allocate<std::byte>(
					encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
			span<std::byte> decrypted_backup{
					decrypted_backup_content,
					encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES};

			//decrypt the backup
			auto status_int{crypto_secretbox_open_easy(
					byte_to_uchar(decrypted_backup.data()),
					encrypted_backup_struct->encrypted_backup.data,
					encrypted_backup_struct->encrypted_backup.len,
					encrypted_backup_struct->encrypted_backup_nonce.data,
					backup_key)};
			if (status_int != 0) {
				throw Exception{status_type::DECRYPT_ERROR, "Failed to decrypt backup."};
			}

			//unpack the struct
			auto arena_protoc_allocator{arena.getProtobufCAllocator()};
			auto backup_struct{molch__protobuf__backup__unpack(&arena_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()))};
			if (backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack backups protobuf-c."};
			}

			//import the user store
			TRY_WITH_RESULT(imported_user_store, UserStore::import({backup_struct->users, backup_struct->n_users}));

			TRY_VOID(update_backup_key(new_backup_key, new_backup_key_length));

			//everyting worked, switch to the new user store
			users = std::move(imported_user_store.value());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_get_prekey_list(
			//output
			unsigned char ** const prekey_list,  //free after use
			size_t * const prekey_list_length,
			//input
			unsigned char * const public_master_key,
			const size_t public_master_key_length) {
		try {
			Expects((public_master_key != nullptr)
					&& (prekey_list != nullptr)
					&& (prekey_list_length != nullptr)
					&& (public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

			TRY_WITH_RESULT(public_signing_key_key_result, PublicSigningKey::fromSpan({uchar_to_byte(public_master_key), PUBLIC_MASTER_KEY_SIZE}));
			const auto& public_signing_key_key{public_signing_key_key_result.value()};
			TRY_WITH_RESULT(prekey_list_buffer_result, create_prekey_list(public_signing_key_key));
			auto& prekey_list_buffer{prekey_list_buffer_result.value()};
			MallocBuffer malloced_prekey_list{prekey_list_buffer.size(), 0};
			TRY_VOID(malloced_prekey_list.cloneFrom(prekey_list_buffer));
			*prekey_list_length = malloced_prekey_list.size();
			*prekey_list = byte_to_uchar(malloced_prekey_list.release());
		} catch (const Exception& exception) {
			return exception.toReturnStatus();
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_update_backup_key(
			unsigned char * const new_key, //output, BACKUP_KEY_SIZE
			const size_t new_key_length) {

		try {
			const auto result{update_backup_key(new_key, new_key_length)};
			if (result.has_error()) {
				return result.error().toReturnStatus();
			}
		} catch (const std::exception& exception) {
			return Exception(status_type::EXCEPTION, exception.what()).toReturnStatus();
		}

		return success_status;
	}
