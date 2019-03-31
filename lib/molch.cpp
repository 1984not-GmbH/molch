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

#include "molch.h"
#include "molch/constants.h"

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
		if (global_backup_key == nullptr) {
			std::terminate();
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
			std::terminate();
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

constexpr auto PREKEYS_SIZE = PREKEY_AMOUNT * PUBLIC_KEY_SIZE;
constexpr auto PREKEY_LIST_EXPIRATION_DATE_OFFSET = PUBLIC_KEY_SIZE + PREKEYS_SIZE;

/*
 * Create a prekey list.
 */
static result<MallocBuffer> create_prekey_list(const PublicSigningKey& public_signing_key) {
	//get the user
	auto user{users.find(public_signing_key)};
	if (user == nullptr) {
		return Error(status_type::NOT_FOUND, "Couldn't find the user to create a prekey list from.");
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
	auto prekey_subspan = span<std::byte>(unsigned_prekey_list).subspan(PUBLIC_KEY_SIZE, PREKEYS_SIZE);
	OUTCOME_TRY(copyFromTo(prekey_list_buffer, prekey_subspan));

	//add the expiration date
	int64_t expiration_date{now().count() + seconds{3_months}.count()};
	auto big_endian_expiration_date = span<std::byte>(unsigned_prekey_list).subspan(PREKEY_LIST_EXPIRATION_DATE_OFFSET, sizeof(int64_t));
	OUTCOME_TRY(to_big_endian(expiration_date, big_endian_expiration_date));

	//sign the prekey list with the current identity key
	MallocBuffer prekey_list{
			unsigned_prekey_list.size() + SIGNATURE_SIZE,
			unsigned_prekey_list.size() + SIGNATURE_SIZE};
	OUTCOME_TRY(signed_data, user->masterKeys().sign(unsigned_prekey_list));
	OUTCOME_TRY(copyFromTo(signed_data, prekey_list));

	return prekey_list;
}

	static result<BackupKey> update_backup_key() {
		OUTCOME_TRY(Molch::sodium_init());

		// create a backup key buffer if it doesnt exist already
		if (global_backup_key == nullptr) {
			global_backup_key = std::unique_ptr<BackupKey,SodiumDeleter<BackupKey>>(sodium_malloc<BackupKey>(1));
			new (global_backup_key.get()) BackupKey();
		}

		//make the content of the backup key writable
		GlobalBackupKeyWriteUnlocker unlocker;

		randombytes_buf(*global_backup_key);
		return *global_backup_key;
	}

	static result<MallocBuffer> export_all() {
		GlobalBackupKeyUnlocker unlocker;
		if (global_backup_key == nullptr) {
			return Error(status_type::INCORRECT_DATA, "No backup key found.");
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
			return Error(status_type::ENCRYPT_ERROR, "Failed to enrypt conversation state.");
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
			return Error(status_type::PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation.");
		}

		return malloced_encrypted_backup;
	}


	enum class CreateBackup: bool {
		YES = true,
		NO = false,
	};

	struct CreateUserResult {
		PublicSigningKey user_id;
		MallocBuffer prekey_list;
		BackupKey backup_key;
		std::optional<MallocBuffer> backup;
	};

	static result<CreateUserResult> create_user(const CreateBackup create_backup, const std::optional<span<const std::byte>> random_spice) {
		OUTCOME_TRY(Molch::sodium_init());

		CreateUserResult user_result;

		//create a new backup key
		OUTCOME_TRY(updated_backup_key, update_backup_key());
		user_result.backup_key = updated_backup_key;

		//create the user
		OUTCOME_TRY(user, Molch::User::create(random_spice));
		user_result.user_id = user.id();
		users.add(std::move(user));

		OUTCOME_TRY(prekey_list, create_prekey_list(user_result.user_id));
		user_result.prekey_list = std::move(prekey_list);

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(backup, export_all());
			user_result.backup = std::move(backup);
		}

		return user_result;
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
	if ((public_master_key == nullptr) or (public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
			or (prekey_list == nullptr) or (prekey_list_length == nullptr)
			or (backup_key == nullptr) or (backup_key_length != BACKUP_KEY_SIZE)
			or ((backup != nullptr) and (backup_length == nullptr))) {
		return {status_type::INVALID_VALUE, "Invalid input to molch_create_user"};
	}
	try {
		const auto create_backup{[&](){
			if (backup == nullptr) {
				return CreateBackup::NO;
			}

			return CreateBackup::YES;
		}()};
		const auto random_spice{[&]() -> std::optional<span<const std::byte>> {
			if (random_data == nullptr) {
				return std::nullopt;
			}

			return {{uchar_to_byte(random_data), random_data_length}};
		}()};
		auto created_user_result = create_user(create_backup, random_spice);
		if (created_user_result.has_error()) {
			return created_user_result.error().toReturnStatus();
		}
		auto& created_user{created_user_result.value()};
		if (create_backup == CreateBackup::YES) {
			auto& backup_buffer{created_user.backup.value()};
			*backup_length = backup_buffer.size();
			*backup = byte_to_uchar(backup_buffer.release());
		}
		*prekey_list_length = created_user.prekey_list.size();
		*prekey_list = byte_to_uchar(created_user.prekey_list.release());
		std::copy(std::cbegin(created_user.backup_key), std::cend(created_user.backup_key), uchar_to_byte(backup_key));
		std::copy(std::cbegin(created_user.user_id), std::cend(created_user.user_id), uchar_to_byte(public_master_key));
	} catch (const std::exception& exception) {
		return {status_type::EXCEPTION, exception.what()};
	}

	return success_status;
}

	static result<std::optional<MallocBuffer>> destroy_user(const span<const std::byte> user_id, CreateBackup create_backup) {
		OUTCOME_TRY(id, PublicSigningKey::fromSpan(user_id));
		users.remove(id);
		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(backup, export_all());
			return std::move(backup);
		}

		return std::nullopt;
	}

MOLCH_PUBLIC(return_status) molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	if ((public_master_key == nullptr) or (public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
			or ((backup != nullptr) and (backup_length == nullptr))) {
		return {status_type::INVALID_VALUE, "Invalid input to molch_destroy_user."};
	}

	try {
		const auto create_backup{[&](){
			if (backup == nullptr) {
				return CreateBackup::NO;
			}

			return CreateBackup::YES;
		}()};
		auto backup_result = destroy_user({uchar_to_byte(public_master_key), public_master_key_length}, create_backup);
		if (backup_result.has_error()) {
			return backup_result.error().toReturnStatus();
		}
		if (create_backup == CreateBackup::YES) {
			auto& created_backup{backup_result.value().value()};
			*backup_length = created_backup.size();
			*backup = byte_to_uchar(created_backup.release());
		}
	} catch (const std::exception& exception) {
		return {status_type::EXCEPTION, exception.what()};
	}

	return success_status;
}

MOLCH_PUBLIC(size_t) molch_user_count() {
	return users.size();
}

MOLCH_PUBLIC(void) molch_destroy_all_users() {
	users.clear();
}

	struct ListedUsers {
		MallocBuffer list;
		size_t count{0};
	};

	static result<ListedUsers> list_users() {
		ListedUsers listed_users;
		OUTCOME_TRY(list, users.list());
		listed_users.list = list;
		listed_users.count = (list.size() / PUBLIC_MASTER_KEY_SIZE);
		return std::move(listed_users);
	}

	MOLCH_PUBLIC(return_status) molch_list_users(
			unsigned char **const user_list,
			size_t * const user_list_length, //length in bytes
			size_t * const count) {
		if ((user_list == nullptr) or (user_list_length == nullptr) or (count == nullptr)) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_list_users"};
		}
		try {
			auto listed_users_result = list_users();
			if (listed_users_result.has_error()) {
				return listed_users_result.error().toReturnStatus();
			}
			auto& listed_users{listed_users_result.value()};
			*count = listed_users.count;
			*user_list_length = listed_users.list.size();
			*user_list = byte_to_uchar(listed_users.list.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
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
	constexpr auto prekeys_size = PREKEY_AMOUNT * PUBLIC_KEY_SIZE;
	constexpr auto expiration_date_offset = PUBLIC_KEY_SIZE + prekeys_size;
	const auto big_endian_expiration_date = span<std::byte>(verified_prekey_list).subspan(expiration_date_offset, sizeof(int64_t));
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

	struct SendConversationResult {
		ConversationId conversation_id;
		MallocBuffer packet;
		std::optional<MallocBuffer> backup;
	};

	static result<SendConversationResult> start_send_conversation(
			const span<const std::byte> sender_id,
			const span<const std::byte> receiver_id,
			const span<const std::byte> prekey_list,
			const span<const std::byte> message,
			const CreateBackup create_backup) {
		//get the user that matches the public signing key of the sender
		OUTCOME_TRY(sender_public_master_key, PublicSigningKey::fromSpan(sender_id));
		auto user{users.find(sender_public_master_key)};
		if (user == nullptr) {
			return Error(status_type::NOT_FOUND, "User not found.");
		}

		//get the receivers public ephemeral and identity
		OUTCOME_TRY(receiver_public_master_key, PublicSigningKey::fromSpan(receiver_id));
		OUTCOME_TRY(receiver_public_identity, verify_prekey_list(prekey_list, receiver_public_master_key));

		MasterKeys::Unlocker unlocker{user->masterKeys()};

		//create the conversation and encrypt the message
		const auto prekeys{prekey_list.subspan(PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list.size() - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t))};
		OUTCOME_TRY(private_identity_key, user->masterKeys().getPrivateIdentityKey());
		OUTCOME_TRY(send_conversation, Molch::Conversation::createSendConversation(
				message,
				user->masterKeys().getIdentityKey(),
				*private_identity_key,
				receiver_public_identity,
				prekeys));

		SendConversationResult conversation_result;
		conversation_result.conversation_id = send_conversation.conversation.id();
		user->conversations.add(std::move(send_conversation.conversation));

		conversation_result.packet = send_conversation.packet;

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(backup, export_all());
			conversation_result.backup = std::move(backup);
		}

		return conversation_result;
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
		if ((conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)
				or (packet == nullptr) or (packet_length == nullptr)
				or (sender_public_master_key == nullptr) or (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				or (receiver_public_master_key == nullptr) or (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				or (prekey_list == nullptr) or (prekey_list_length < (PUBLIC_KEY_SIZE + SIGNATURE_SIZE + sizeof(int64_t)))
				or (message == nullptr)
				or ((backup != nullptr) and (backup_length == nullptr))) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_start_send_conversation"};
		}

		try {
			const auto create_backup{[&](){
				if (backup == nullptr) {
					return CreateBackup::NO;
				}

				return CreateBackup::YES;
			}()};
			auto conversation_result = start_send_conversation(
					{uchar_to_byte(sender_public_master_key), sender_public_master_key_length},
					{uchar_to_byte(receiver_public_master_key), receiver_public_master_key_length},
					{uchar_to_byte(prekey_list), prekey_list_length},
					{uchar_to_byte(message), message_length},
					create_backup);
			if (conversation_result.has_error()) {
				return conversation_result.error().toReturnStatus();
			}
			auto& conversation{conversation_result.value()};
			std::copy(std::cbegin(conversation.conversation_id), std::cend(conversation.conversation_id), uchar_to_byte(conversation_id));
			if (create_backup == CreateBackup::YES) {
				auto& created_backup{conversation.backup.value()};
				*backup_length = created_backup.size();
				*backup = byte_to_uchar(created_backup.release());
			}
			*packet_length = conversation.packet.size();
			*packet = byte_to_uchar(conversation.packet.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	struct ReceiveConversationResult {
		ConversationId conversation_id;
		MallocBuffer prekey_list;
		MallocBuffer message;
		std::optional<MallocBuffer> backup;
	};

	static result<ReceiveConversationResult> start_receive_conversation(
			const span<const std::byte> receiver_id,
			const span<const std::byte> sender_id,
			const span<const std::byte> packet,
			CreateBackup create_backup) {
		(void)sender_id;
		//get the user that matches the public signing key of the receiver
		OUTCOME_TRY(receiver_public_master_key, PublicSigningKey::fromSpan(receiver_id));
		auto user{users.find(receiver_public_master_key)};
		if (user == nullptr) {
			return Error(status_type::NOT_FOUND, "User not found in the user store.");
		}

		//unlock the master keys
		MasterKeys::Unlocker unlocker(user->masterKeys());

		//create the conversation
		OUTCOME_TRY(private_identity_key, user->masterKeys().getPrivateIdentityKey());
		OUTCOME_TRY(receive_conversation, Molch::Conversation::createReceiveConversation(
				packet,
				user->masterKeys().getIdentityKey(),
				*private_identity_key,
				user->prekeys));

		//copy the conversation id
		ReceiveConversationResult conversation_result;
		conversation_result.conversation_id = receive_conversation.conversation.id();

		//create the prekey list
		OUTCOME_TRY(prekey_list, create_prekey_list(receiver_public_master_key));
		conversation_result.prekey_list = std::move(prekey_list);

		//add the conversation to the conversation store
		user->conversations.add(std::move(receive_conversation.conversation));

		//copy the message
		conversation_result.message = receive_conversation.message;

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(backup, export_all());
			conversation_result.backup = std::move(backup);
		}

		return conversation_result;
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
		if ((conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)
				or (prekey_list == nullptr) or (prekey_list_length == nullptr)
				or (message == nullptr) or (message_length == nullptr)
				or (receiver_public_master_key == nullptr) or (receiver_public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				or (sender_public_master_key == nullptr) or (sender_public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				or (packet == nullptr)
				or ((backup != nullptr) and (backup_length == nullptr))) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_start_receive_conversation"};
		}

		try {
			const auto create_backup{[&](){
				if (backup == nullptr) {
					return CreateBackup::NO;
				}

				return CreateBackup::YES;
			}()};
			auto conversation_result = start_receive_conversation(
					{uchar_to_byte(receiver_public_master_key), receiver_public_master_key_length},
					{uchar_to_byte(sender_public_master_key), sender_public_master_key_length},
					{uchar_to_byte(packet), packet_length},
					create_backup);
			if (conversation_result.has_error()) {
				return conversation_result.error().toReturnStatus();
			}
			auto& conversation{conversation_result.value()};
			std::copy(std::cbegin(conversation.conversation_id), std::cend(conversation.conversation_id), uchar_to_byte(conversation_id));

			*prekey_list_length = conversation.prekey_list.size();
			*prekey_list = byte_to_uchar(conversation.prekey_list.release());

			*message_length = conversation.message.size();
			*message = byte_to_uchar(conversation.message.release());

			if (create_backup == CreateBackup::YES) {
				auto& created_backup{conversation.backup.value()};
				*backup_length = created_backup.size();
				*backup = byte_to_uchar(created_backup.release());
			}
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
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
			return Error(status_type::NOT_FOUND, "Failed to find the conversation.");
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

	struct EncryptResult {
		MallocBuffer packet;
		std::optional<MallocBuffer> conversation_backup;
	};

	static result<EncryptResult> encrypt_message(
			const span<const std::byte> conversation_id,
			const span<const std::byte> message,
			const CreateBackup create_backup) {
		//find the conversation
		OUTCOME_TRY(conversation_id_key, ConversationId::fromSpan(conversation_id));
		Molch::User *user;
		auto conversation{users.findConversation(user, conversation_id_key)};
		if (conversation == nullptr) {
			return Error(status_type::NOT_FOUND, "Failed to find a conversation for the given ID.");
		}

		OUTCOME_TRY(packet, conversation->send(message, std::nullopt));

		EncryptResult encrypt_result;
		encrypt_result.packet = packet;

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(conversation_backup, export_conversation(conversation_id));
			encrypt_result.conversation_backup = std::move(conversation_backup);
		}

		return encrypt_result;
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
		if ((packet == nullptr) or (packet_length == nullptr)
				or (conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)
				or (message == nullptr)
				or ((conversation_backup != nullptr) and (conversation_backup_length == nullptr))) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_encrypt_message"};
		}

		try {
			const auto create_backup{[&](){
				if (conversation_backup == nullptr) {
					return CreateBackup::NO;
				}

				return CreateBackup::YES;
			}()};
			auto encrypted_message_result = encrypt_message(
					{uchar_to_byte(conversation_id), conversation_id_length},
					{uchar_to_byte(message), message_length},
					create_backup);
			if (encrypted_message_result.has_error()) {
				return encrypted_message_result.error().toReturnStatus();
			}
			auto& encrypted_message{encrypted_message_result.value()};

			*packet_length = encrypted_message.packet.size();
			*packet = byte_to_uchar(encrypted_message.packet.release());

			if (create_backup == CreateBackup::YES) {
				auto& backup{encrypted_message.conversation_backup.value()};
				*conversation_backup_length = backup.size();
				*conversation_backup = byte_to_uchar(backup.release());
			}
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	struct DecryptResult {
		uint32_t message_number = 0;
		uint32_t previous_message_number = 0;
		MallocBuffer message;
		std::optional<MallocBuffer> conversation_backup;
	};

	static result<DecryptResult> decrypt_message(
			const span<const std::byte> conversation_id,
			const span<const std::byte> packet,
			const CreateBackup create_backup) {
		//find the conversation
		OUTCOME_TRY(conversation_id_key, ConversationId::fromSpan(conversation_id));
		Molch::User* user;
		auto conversation{users.findConversation(user, conversation_id_key)};
		if (conversation == nullptr) {
			return Error(status_type::NOT_FOUND, "Failed to find conversation with the given ID.");
		}

		OUTCOME_TRY(received_message, conversation->receive(packet));

		DecryptResult decrypt_result;

		decrypt_result.message = received_message.message;
		decrypt_result.message_number = received_message.message_number;
		decrypt_result.previous_message_number = received_message.previous_message_number;

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(created_backup, export_conversation(conversation_id));
			decrypt_result.conversation_backup = std::move(created_backup);
		}

		return decrypt_result;
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
			size_t * const conversation_backup_length) {
		if ((message == nullptr) or (message_length == nullptr)
				or (receive_message_number == nullptr) or (previous_receive_message_number == nullptr)
				or (conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)
				or (packet == nullptr)
				or ((conversation_backup != nullptr) and (conversation_backup_length == nullptr))) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_decrypt_message."};
		}

		try {
			const auto create_backup{[&](){
				if (conversation_backup == nullptr) {
					return CreateBackup::NO;
				}

				return CreateBackup::YES;
			}()};
			auto decrypted_message_result = decrypt_message(
					{uchar_to_byte(conversation_id), conversation_id_length},
					{uchar_to_byte(packet), packet_length},
					create_backup);
			if (decrypted_message_result.has_error()) {
				return decrypted_message_result.error().toReturnStatus();
			}
			auto& decrypted_message = decrypted_message_result.value();

			*message_length = decrypted_message.message.size();
			*message = byte_to_uchar(decrypted_message.message.release());

			*receive_message_number = decrypted_message.message_number;
			*previous_receive_message_number = decrypted_message.previous_message_number;

			if (create_backup == CreateBackup::YES) {
				auto& created_backup = decrypted_message.conversation_backup.value();
				*conversation_backup_length = created_backup.size();
				*conversation_backup = byte_to_uchar(created_backup.release());
			}
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	static result<std::optional<MallocBuffer>> end_conversation(const span<const std::byte> conversation_id_span, CreateBackup create_backup) {
		//find the conversation
		OUTCOME_TRY(conversation_id, ConversationId::fromSpan(conversation_id_span));
		Molch::User *user{nullptr};
		auto conversation{users.findConversation(user, conversation_id)};
		if (conversation == nullptr) {
			return Error(status_type::NOT_FOUND, "Couldn't find conversation.");
		}

		user->conversations.remove(conversation_id);

		if (create_backup == CreateBackup::YES) {
			OUTCOME_TRY(created_backup, export_all());
			return {std::move(created_backup)};
		}

		return std::nullopt;
	}

	MOLCH_PUBLIC(return_status) molch_end_conversation(
			//input
			const unsigned char * const conversation_id,
			const size_t conversation_id_length,
			//optional output (can be nullptr)
			unsigned char ** const backup,
			size_t * const backup_length
			) {
		if ((conversation_id == nullptr) or (conversation_id_length != CONVERSATION_ID_SIZE)
				or ((backup != nullptr) and (backup_length == nullptr))) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_end_conversation"};
		}
		try {
			const auto create_backup{[&](){
				if (backup == nullptr) {
					return CreateBackup::NO;
				}

				return CreateBackup::YES;
			}()};

			auto backup_result = end_conversation({uchar_to_byte(conversation_id), conversation_id_length}, create_backup);
			if (backup_result.has_error()) {
				return backup_result.error().toReturnStatus();
			}
			if (create_backup == CreateBackup::YES) {
				auto& created_backup{backup_result.value().value()};
				*backup_length = created_backup.size();
				*backup = byte_to_uchar(created_backup.release());
			}
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	struct ConversationList {
		MallocBuffer list;
		size_t amount = 0;
	};

	static result<ConversationList> list_conversations(const span<const std::byte> user_public_master_key_span) {
		OUTCOME_TRY(user_public_master_key, PublicSigningKey::fromSpan(user_public_master_key_span));
		auto user = users.find(user_public_master_key);
		if (user == nullptr) {
			return Error(status_type::NOT_FOUND, "No user found for the given public identity.");
		}

		ConversationList conversation_list;
		OUTCOME_TRY(conversation_list_buffer, user->conversations.list());
		if (conversation_list_buffer.empty()) {
			conversation_list.amount = 0;
			return conversation_list;
		}

		if ((conversation_list_buffer.size() % CONVERSATION_ID_SIZE) != 0) {
			return Error(status_type::INCORRECT_BUFFER_SIZE, "The conversation ID buffer has an incorrect length.");
		}
		conversation_list.amount = conversation_list_buffer.size() / CONVERSATION_ID_SIZE;

		conversation_list.list = conversation_list_buffer;
		return conversation_list;
	}

	MOLCH_PUBLIC(return_status) molch_list_conversations(
			//outputs
			unsigned char ** const conversation_list,
			size_t * const conversation_list_length,
			size_t * const number,
			//inputs
			const unsigned char * const user_public_master_key,
			const size_t user_public_master_key_length) {
		if ((user_public_master_key == nullptr)
				|| (user_public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				|| (conversation_list == nullptr)
				|| (conversation_list_length == nullptr)
				|| (number == nullptr)) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_list_conversations."};
		}

		try {
			auto conversation_list_result = list_conversations({uchar_to_byte(user_public_master_key), user_public_master_key_length});
			if (conversation_list_result.has_error()) {
				return conversation_list_result.error().toReturnStatus();
			}
			auto& conversation_list_value = conversation_list_result.value();

			*number = conversation_list_value.amount;
			*conversation_list_length = conversation_list_value.list.size();
			*conversation_list = byte_to_uchar(conversation_list_value.list.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
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
			auto encrypted_backup_result = export_conversation({uchar_to_byte(conversation_id), conversation_id_length});
			if (encrypted_backup_result.has_error()) {
				return encrypted_backup_result.error().toReturnStatus();
			}
			auto& encrypted_backup{encrypted_backup_result.value()};
			*backup_length = encrypted_backup.size();
			*backup = byte_to_uchar(encrypted_backup.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	static result<BackupKey> import_conversation(const span<const std::byte> backup, const span<const std::byte> backup_key) {
		//unpack the encrypted backup
		auto encrypted_backup_struct = std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, std::size(backup), byte_to_uchar(std::data(backup))));
		if (encrypted_backup_struct == nullptr) {
			return Error(status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
		}

		//check the backup
		if (encrypted_backup_struct->backup_version != 0) {
			return Error(status_type::INCORRECT_DATA, "Incompatible backup.");
		}
		if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
			return Error(status_type::INCORRECT_DATA, "Backup is not a conversation backup.");
		}
		if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state.");
		}
		if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
		}

		Arena arena;
		auto decrypted_backup_content = arena.allocate<std::byte>(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES);
		auto decrypted_backup = span<std::byte>(decrypted_backup_content, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES);

		//decrypt the backup
		OUTCOME_TRY(crypto_secretbox_open_easy(
				decrypted_backup,
				{uchar_to_byte(encrypted_backup_struct->encrypted_backup.data), encrypted_backup_struct->encrypted_backup.len},
				{uchar_to_byte(encrypted_backup_struct->encrypted_backup_nonce.data), encrypted_backup_struct->encrypted_backup_nonce.len},
				backup_key));

		//unpack the struct
		auto arena_protoc_allocator = arena.getProtobufCAllocator();
		auto conversation_struct = molch__protobuf__conversation__unpack(&arena_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()));
		if (conversation_struct == nullptr) {
			return Error(status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversations protobuf-c.");
		}

		//import the conversation
		ProtobufCConversation conversation_pointer{*conversation_struct};
		Molch::User* containing_user{nullptr};
		OUTCOME_TRY(conversation_id_key, ConversationId::fromSpan({conversation_struct->id}));
		auto existing_conversation{users.findConversation(containing_user, conversation_id_key)};
		if (existing_conversation == nullptr) {
			return Error(status_type::NOT_FOUND, "Containing store not found.");
		}

		OUTCOME_TRY(conversation, Conversation::import(conversation_pointer));
		containing_user->conversations.add(std::move(conversation));

		OUTCOME_TRY(updated_backup_key, update_backup_key());
		return std::move(updated_backup_key);
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
		if ((backup == nullptr)
				|| (backup_key == nullptr) || (backup_key_length != BACKUP_KEY_SIZE)
				|| (new_backup_key == nullptr) || (new_backup_key_length != BACKUP_KEY_SIZE)) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_conversation_import"};
		}

		try {
			const auto new_backup_key_key_result = import_conversation({uchar_to_byte(backup), backup_length}, {uchar_to_byte(backup_key), backup_key_length});
			if (new_backup_key_key_result.has_error()) {
				return new_backup_key_key_result.error().toReturnStatus();
			}
			const auto& new_backup_key_key = new_backup_key_key_result.value();
			std::copy(std::cbegin(new_backup_key_key), std::cend(new_backup_key_key), uchar_to_byte(new_backup_key));
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_export(
			unsigned char ** const backup,
			size_t *backup_length) {
		if ((backup == nullptr) or (backup_length == nullptr)) {
			return {status_type::INVALID_VALUE, "backup or backup_length are NULL"};
		}

		try {
			auto exported_backup_result{export_all()};
			if (exported_backup_result.has_error()) {
				return exported_backup_result.error().toReturnStatus();
			}
			auto& exported_backup{exported_backup_result.value()};
			//now pack the entire backup
			*backup_length = exported_backup.size();
			*backup = byte_to_uchar(exported_backup.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	static result<BackupKey> import_all(const span<const std::byte> backup, const span<const std::byte> backup_key) {
		OUTCOME_TRY(Molch::sodium_init());

		//unpack the encrypted backup
		auto encrypted_backup_struct = std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(molch__protobuf__encrypted_backup__unpack(&protobuf_c_allocator, backup.size(), byte_to_uchar(backup.data())));
		if (encrypted_backup_struct == nullptr) {
			return Error(status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf.");
		}

		//check the backup
		if (encrypted_backup_struct->backup_version != 0) {
			return Error(status_type::INCORRECT_DATA, "Incompatible backup.");
		}
		if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != MOLCH__PROTOBUF__ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
			return Error(status_type::INCORRECT_DATA, "Backup is not a full backup.");
		}
		if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted state.");
		}
		if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
			return Error(status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce.");
		}

		Arena arena;
		auto decrypted_backup_content = arena.allocate<std::byte>(encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES);
		auto decrypted_backup = span<std::byte>(decrypted_backup_content, encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES);

		//decrypt the backup
		OUTCOME_TRY(crypto_secretbox_open_easy(
				decrypted_backup,
				{uchar_to_byte(encrypted_backup_struct->encrypted_backup.data), encrypted_backup_struct->encrypted_backup.len},
				{uchar_to_byte(encrypted_backup_struct->encrypted_backup_nonce.data), encrypted_backup_struct->encrypted_backup_nonce.len},
				backup_key));

		//unpack the struct
		auto arena_protoc_allocator = arena.getProtobufCAllocator();
		auto backup_struct{molch__protobuf__backup__unpack(&arena_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()))};
		if (backup_struct == nullptr) {
			return Error(status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack backups protobuf-c.");
		}

		//import the user store
		OUTCOME_TRY(imported_user_store, UserStore::import({backup_struct->users, backup_struct->n_users}));

		OUTCOME_TRY(updated_backup_key, update_backup_key());

		//everything worked, switch to the new user store
		users = std::move(imported_user_store);

		return std::move(updated_backup_key);
	}

	MOLCH_PUBLIC(return_status) molch_import(
			//output
			unsigned char * const new_backup_key, //BACKUP_KEY_SIZE, can be the same pointer as the backup key
			const size_t new_backup_key_length,
			//inputs
			const unsigned char * const backup,
			const size_t backup_length,
			const unsigned char * const backup_key, //BACKUP_KEY_SIZE
			const size_t backup_key_length
			) {
		if ((backup == nullptr)
				|| (backup_key == nullptr) || (backup_key_length != BACKUP_KEY_SIZE)
				|| (new_backup_key == nullptr) || (new_backup_key_length != BACKUP_KEY_SIZE)) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_import"};
		}

		try {
			const auto new_backup_key_key_result = import_all({uchar_to_byte(backup), backup_length}, {uchar_to_byte(backup_key), backup_key_length});
			if (new_backup_key_key_result.has_error()) {
				return new_backup_key_key_result.error().toReturnStatus();
			}
			const auto& new_backup_key_key = new_backup_key_key_result.value();
			std::copy(std::cbegin(new_backup_key_key), std::cend(new_backup_key_key), uchar_to_byte(new_backup_key));
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	static result<MallocBuffer> get_prekey_list(const span<const std::byte> public_master_key) {
		OUTCOME_TRY(public_signing_key_key, PublicSigningKey::fromSpan(public_master_key));
		OUTCOME_TRY(prekey_list_buffer, create_prekey_list(public_signing_key_key));
		MallocBuffer malloced_prekey_list{prekey_list_buffer.size(), 0};
		OUTCOME_TRY(malloced_prekey_list.cloneFrom(prekey_list_buffer));

		return std::move(malloced_prekey_list);
	}

	MOLCH_PUBLIC(return_status) molch_get_prekey_list(
			//output
			unsigned char ** const prekey_list,  //free after use
			size_t * const prekey_list_length,
			//input
			unsigned char * const public_master_key,
			const size_t public_master_key_length) {
		if ((public_master_key == nullptr) || (public_master_key_length != PUBLIC_MASTER_KEY_SIZE)
				|| (prekey_list == nullptr)
				|| (prekey_list_length == nullptr)) {
			return {status_type::INVALID_VALUE, "Invalid input to molch_get_prekey_list."};
		}

		try {
			auto malloced_prekey_list_result = get_prekey_list({uchar_to_byte(public_master_key), public_master_key_length});
			if (malloced_prekey_list_result.has_error()) {
				return malloced_prekey_list_result.error().toReturnStatus();
			}
			auto& malloced_prekey_list = malloced_prekey_list_result.value();
			*prekey_list_length = malloced_prekey_list.size();
			*prekey_list = byte_to_uchar(malloced_prekey_list.release());
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}

	MOLCH_PUBLIC(return_status) molch_update_backup_key(
			unsigned char * const new_key, //output, BACKUP_KEY_SIZE
			const size_t new_key_length) {
		if ((new_key == nullptr) or (new_key_length != BACKUP_KEY_SIZE)) {
			return {status_type::INVALID_VALUE, "No new backup key or invalid size"};
		}

		try {
			const auto updated_backup_key_result = update_backup_key();
			if (updated_backup_key_result.has_error()) {
				return updated_backup_key_result.error().toReturnStatus();
			}
			const auto& updated_backup_key{updated_backup_key_result.value()};
			std::copy(std::cbegin(updated_backup_key), std::cend(updated_backup_key), uchar_to_byte(new_key));
		} catch (const std::exception& exception) {
			return {status_type::EXCEPTION, exception.what()};
		}

		return success_status;
	}


	static result<std::array<int64_t,PREKEY_AMOUNT>> get_prekey_list_expiration_seconds(const span<const std::byte> user_id) {
		OUTCOME_TRY(public_signing_key, PublicSigningKey::fromSpan(user_id));
		auto user{users.find(public_signing_key)};
		if (user == nullptr) {
			return Error(status_type::NOT_FOUND, "User not found.");
		}

		auto expiration_dates{user->prekeys.listExpirationDates()};
		std::array<int64_t,PREKEY_AMOUNT> expiration_date_ints;
		// TODO: Is this cast correct?
		std::transform(std::begin(expiration_dates), std::end(expiration_dates), std::begin(expiration_date_ints),
				[](auto date) { return static_cast<int64_t>(date.count()); });

		return expiration_date_ints;
	}

	MOLCH_PUBLIC(return_status) molch_get_prekey_list_expiration_seconds(
			//output
			int64_t ** const prekey_expiration_seconds, //free after use
			size_t * const prekey_expiration_seconds_length,
			//input
			const unsigned char * const public_master_key,
			const size_t public_master_key_length) {
		if ((prekey_expiration_seconds == nullptr) or (prekey_expiration_seconds_length == nullptr)) {
			return {status_type::INVALID_VALUE, "No prekey_expiration_seconds output or length specified."};
		}

		if (public_master_key == nullptr) {
			return {status_type::INVALID_VALUE, "No public_master_key given."};
		}

		const auto expiration_date_list_result{get_prekey_list_expiration_seconds({uchar_to_byte(public_master_key), public_master_key_length})};
		if (expiration_date_list_result.has_error()) {
			return expiration_date_list_result.error().toReturnStatus();
		}
		const auto expiration_date_list{expiration_date_list_result.value()};

		auto malloced_list{reinterpret_cast<int64_t*>(malloc(sizeof(int64_t) * std::size(expiration_date_list)))};
		if (malloced_list == nullptr) {
			*prekey_expiration_seconds = nullptr;
			*prekey_expiration_seconds_length = 0;
			return {status_type::ALLOCATION_FAILED, "Failed to allocate list of expiration dates."};
		}

		std::copy(std::begin(expiration_date_list), std::end(expiration_date_list), malloced_list);
		*prekey_expiration_seconds = malloced_list;
		*prekey_expiration_seconds_length = std::size(expiration_date_list);


		return success_status;
	}
