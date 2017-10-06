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
#include "key.hpp"
#include "gsl.hpp"

using namespace Molch;

//global user store
static std::unique_ptr<UserStore> users;
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

	~GlobalBackupKeyUnlocker() {
		try {
			Molch::sodium_mprotect_noaccess(global_backup_key.get());
		} catch (...) {
			std::terminate();
		}
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

	~GlobalBackupKeyWriteUnlocker() {
		try {
			Molch::sodium_mprotect_noaccess(global_backup_key.get());
		} catch (...) {
			std::terminate();
		}
	}
};

/*
 * Create a prekey list.
 */
static MallocBuffer create_prekey_list(const PublicSigningKey& public_signing_key) {
	//get the user
	auto user{users->find(public_signing_key)};
	if (user == nullptr) {
		throw Exception{status_type::NOT_FOUND, "Couldn't find the user to create a prekey list from."};
	}

	//rotate the prekeys
	user->prekeys().rotate();

	//copy the public identity to the prekey list
	MallocBuffer unsigned_prekey_list{
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t),
			PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE + sizeof(uint64_t)};
	unsigned_prekey_list.copyFromRaw(0, user->masterKeys().getIdentityKey().data(), 0, PUBLIC_KEY_SIZE);

	//get the prekeys
	span<gsl::byte> prekeys{&unsigned_prekey_list[PUBLIC_KEY_SIZE], PREKEY_AMOUNT * PUBLIC_KEY_SIZE};
	user->prekeys().list(prekeys);

	//add the expiration date
	int64_t expiration_date{now().count() + seconds{3_months}.count()};
	span<gsl::byte> big_endian_expiration_date{&unsigned_prekey_list[PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE], sizeof(int64_t)};
	to_big_endian(expiration_date, big_endian_expiration_date);

	//sign the prekey list with the current identity key
	MallocBuffer prekey_list{
			unsigned_prekey_list.size() + SIGNATURE_SIZE,
			unsigned_prekey_list.size() + SIGNATURE_SIZE};
	user->masterKeys().sign(unsigned_prekey_list, prekey_list);

	return prekey_list;
}

/*
 * Create a new user. The user is identified by the public master key.
 *
 * Get's random input (can be in any format and doesn't have
 * to be uniformly distributed) and uses it in combination
 * with the OS's random number generator to generate a
 * signing and identity keypair for the user.
 *
 * IMPORTANT: Don't put random numbers provided by the operating
 * system in there.
 *
 * This also creates a signed list of prekeys to be uploaded to
 * the server.
 *
 * A new backup key is generated that subsequent backups of the library state will be encrypted with.
 *
 * Don't forget to destroy the return status with molch_destroy_return_status()
 * if an error has occurred.
 */
return_status molch_create_user(
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
	auto status{return_status_init()};

	auto user_store_created{false};

	try {
		Expects((public_master_key != nullptr)
			&& (prekey_list != nullptr)
			&& (prekey_list_length != nullptr)
			&& (backup_key_length == BACKUP_KEY_SIZE)
			&& (public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

		//initialise libsodium and create user store
		if (!users) {
			Molch::sodium_init();
			users = std::make_unique<UserStore>();
		}

		//create a new backup key
		{
			auto status{molch_update_backup_key(backup_key, backup_key_length)};
			on_error {
				throw Exception{status};
			}
		}

		//create the user
		PublicSigningKey public_master_key_key;
		if (random_data_length != 0) {
			users->add(Molch::User({uchar_to_byte(random_data), random_data_length}, &public_master_key_key));
		} else {
			users->add(Molch::User(&public_master_key_key));
		}
		public_master_key_key.copyTo({uchar_to_byte(public_master_key), PUBLIC_MASTER_KEY_SIZE});

		user_store_created = true;

		auto prekey_list_buffer = create_prekey_list(public_master_key_key);

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
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(status_type::EXCEPTION, exception.what());
	}

cleanup:
	on_error {
		if (user_store_created) {
			return_status new_status = molch_destroy_user(public_master_key, public_master_key_length, nullptr, nullptr);
			return_status_destroy_errors(new_status);
		}
	}

	return status;
}

/*
 * Destroy a user.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		//optional output (can be nullptr)
		unsigned char **const backup, //exports the entire library state, free after use, check if nullptr before use!
		size_t *const backup_length
) {
	auto status{return_status_init()};

	try {
		if (!users) {
			throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialised yet."};
		}

		if (public_master_key_length != PUBLIC_MASTER_KEY_SIZE) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "Public master key has incorrect size."};
		}

		PublicSigningKey public_master_key_key;
		public_master_key_key.set({uchar_to_byte(public_master_key), PUBLIC_MASTER_KEY_SIZE});
		users->remove(public_master_key_key);

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
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(status_type::EXCEPTION, exception.what());
	}

cleanup:
	return status;
}

/*
 * Get the number of users.
 */
size_t molch_user_count() {
	if (!users) {
		return 0;
	}

	return users->size();
}

/*
 * Delete all users.
 */
void molch_destroy_all_users() {
	if (users) {
		users->clear();
	}
}

/*
 * List all of the users (list of the public keys),
 * nullptr if there are no users.
 *
 * The list is accessible via the return status' 'data' property.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_list_users(
		unsigned char **const user_list,
		size_t * const user_list_length, //length in bytes
		size_t * const count) {
	auto status{return_status_init()};

	try {
		Expects(users && (user_list_length != nullptr));

		//get the list of users and copy it
		auto list{users->list()};

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

/*
 * Get the type of a message.
 *
 * This is either a normal message or a prekey message.
 * Prekey messages mark the start of a new conversation.
 */
molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length) {
	molch_message_type packet_type;

	try {
		uint32_t current_protocol_version;
		uint32_t highest_supported_protocol_version;
		packet_get_metadata_without_verification(
			current_protocol_version,
			highest_supported_protocol_version,
			packet_type,
			{uchar_to_byte(packet), packet_length},
			nullptr,
			nullptr,
			nullptr);
	} catch (const std::exception&) {
		return molch_message_type::INVALID;
	}

	return packet_type;
}

/*
 * Verify prekey list and extract the public identity
 * and choose a prekey.
 */
static void verify_prekey_list(
		const span<const gsl::byte> prekey_list,
		PublicKey& public_identity_key, //output, PUBLIC_KEY_SIZE
		PublicSigningKey& public_signing_key) {
	//verify the signature
	Buffer verified_prekey_list{prekey_list.size() - SIGNATURE_SIZE, prekey_list.size() - SIGNATURE_SIZE};
	crypto_sign_open(
			verified_prekey_list,
			prekey_list,
			public_signing_key);

	//get the expiration date
	int64_t expiration_date;
	span<gsl::byte> big_endian_expiration_date{&verified_prekey_list[PUBLIC_KEY_SIZE + PREKEY_AMOUNT * PUBLIC_KEY_SIZE], sizeof(int64_t)};
	from_big_endian(expiration_date, big_endian_expiration_date);

	//make sure the prekey list isn't too old
	int64_t current_time{now().count()};
	if (expiration_date < current_time) {
		throw Exception{status_type::OUTDATED, "Prekey list has expired (older than 3 months)."};
	}

	//copy the public identity key
	verified_prekey_list.copyToRaw(public_identity_key.data(), 0, 0, PUBLIC_KEY_SIZE);
	public_identity_key.empty = false;
}

/*
 * Start a new conversation. (sending)
 *
 * The conversation can be identified by it's ID
 *
 * This requires a new set of prekeys from the receiver.
 *
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status molch_start_send_conversation(
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
	auto status{return_status_init()};

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

		if (!users) {
			throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialised yet."};
		}

		//get the user that matches the public signing key of the sender
		PublicSigningKey sender_public_master_key_key;
		sender_public_master_key_key.set({uchar_to_byte(sender_public_master_key), PUBLIC_MASTER_KEY_SIZE});
		auto user{users->find(sender_public_master_key_key)};
		if (user == nullptr) {
			throw Exception{status_type::NOT_FOUND, "User not found."};
		}

		//get the receivers public ephemeral and identity
		PublicKey receiver_public_identity;
		PublicSigningKey receiver_public_master_key_key;
		receiver_public_master_key_key.set({uchar_to_byte(receiver_public_master_key), PUBLIC_MASTER_KEY_SIZE});
		verify_prekey_list(
				{uchar_to_byte(prekey_list), prekey_list_length},
				receiver_public_identity,
				receiver_public_master_key_key);

		//unlock the master keys
		MasterKeys::Unlocker unlocker{user->masterKeys()};

		//create the conversation and encrypt the message
		span<const gsl::byte> prekeys{uchar_to_byte(prekey_list) + PUBLIC_KEY_SIZE + SIGNATURE_SIZE, prekey_list_length - PUBLIC_KEY_SIZE - SIGNATURE_SIZE - sizeof(int64_t)};
		Buffer packet_buffer;
		Molch::Conversation conversation{
			{uchar_to_byte(message), message_length},
			packet_buffer,
			user->masterKeys().getIdentityKey(),
			user->masterKeys().getPrivateIdentityKey(),
			receiver_public_identity,
			prekeys};

		//copy the conversation id
		conversation.id().copyTo({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});

		user->conversations().add(std::move(conversation));

		//copy the packet to a malloced buffer output
		MallocBuffer malloced_packet{packet_buffer.size(), 0};
		malloced_packet.cloneFrom(packet_buffer);

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
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(status_type::EXCEPTION, exception.what());
	}

cleanup:
	return status;
}

	/*
	 * Start a new conversation. (receiving)
	 *
	 * This also generates a new set of prekeys to be uploaded to the server.
	 *
	 * This function is called after receiving a prekey message.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	return_status molch_start_receive_conversation(
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

		auto status{return_status_init()};

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

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			//get the user that matches the public signing key of the receiver
			PublicSigningKey receiver_public_master_key_key;
			receiver_public_master_key_key.set({
					uchar_to_byte(receiver_public_master_key),
					PUBLIC_MASTER_KEY_SIZE});
			auto user{users->find(receiver_public_master_key_key)};
			if (user == nullptr) {
				throw Exception{status_type::NOT_FOUND, "User not found in the user store."};
			}

			//unlock the master keys
			MasterKeys::Unlocker unlocker{user->masterKeys()};

			//create the conversation
			Buffer message_buffer;
			Molch::Conversation conversation{
				{uchar_to_byte(packet), packet_length},
				message_buffer,
				user->masterKeys().getIdentityKey(),
				user->masterKeys().getPrivateIdentityKey(),
				user->prekeys()};

			//copy the conversation id
			conversation.id().copyTo({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});

			//create the prekey list
			auto prekey_list_buffer{create_prekey_list(receiver_public_master_key_key)};

			//add the conversation to the conversation store
			user->conversations().add(std::move(conversation));

			//copy the message
			MallocBuffer malloced_message{message_buffer.size(), 0};
			malloced_message.cloneFrom(message_buffer);

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
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * Encrypt a message and create a packet that can be sent to the receiver.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	return_status molch_encrypt_message(
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
		auto status{return_status_init()};

		try {
			Expects((packet != nullptr) && (packet_length != nullptr)
				&& (message != nullptr)
				&& (conversation_id != nullptr)
				&& (conversation_id_length == CONVERSATION_ID_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			//find the conversation
			Molch::Key<CONVERSATION_ID_SIZE,KeyType::Key> conversation_id_key;
			conversation_id_key.set({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});
			Molch::User *user;
			auto conversation{users->findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Failed to find a conversation for the given ID."};
			}

			auto packet_buffer{conversation->send(
					{uchar_to_byte(message), message_length},
					nullptr,
					nullptr,
					nullptr)};

			//copy the packet content
			MallocBuffer malloced_packet{packet_buffer.size(), 0};
			malloced_packet.cloneFrom(packet_buffer);

			if (conversation_backup != nullptr) {
				*conversation_backup = nullptr;
				if (conversation_backup_length != nullptr) {
					auto status{molch_conversation_export(conversation_backup, conversation_backup_length, byte_to_uchar(conversation->id().data()), conversation->id().size())};
					on_error {
						throw Exception{status};
					}
				}
			}

			*packet_length = malloced_packet.size();
			*packet = byte_to_uchar(malloced_packet.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * Decrypt a message.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	return_status molch_decrypt_message(
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
		auto status{return_status_init()};

		try {
			Expects((message != nullptr)
					&& (message_length != nullptr)
					&& (packet != nullptr)
					&& (conversation_id != nullptr)
					&& (receive_message_number != nullptr)
					&& (previous_receive_message_number != nullptr)
					&& (conversation_id_length == CONVERSATION_ID_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			//find the conversation
			Molch::Key<CONVERSATION_ID_SIZE,KeyType::Key> conversation_id_key;
			conversation_id_key.set({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});
			Molch::User* user;
			auto conversation{users->findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Failed to find conversation with the given ID."};
			}

			auto message_buffer{conversation->receive(
					{uchar_to_byte(packet), packet_length},
					*receive_message_number,
					*previous_receive_message_number)};

			//copy the message
			MallocBuffer malloced_message{message_buffer.size(), 0};
			malloced_message.cloneFrom(message_buffer);

			if (conversation_backup != nullptr) {
				*conversation_backup = nullptr;
				if (conversation_backup_length != nullptr) {
					auto status{molch_conversation_export(conversation_backup, conversation_backup_length, byte_to_uchar(conversation->id().data()), conversation->id().size())};
					on_error {
						throw Exception{status};
					}
				}
			}

			*message_length = malloced_message.size();
			*message = byte_to_uchar(malloced_message.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	return_status molch_end_conversation(
			//input
			const unsigned char * const conversation_id,
			const size_t conversation_id_length,
			//optional output (can be nullptr)
			unsigned char ** const backup,
			size_t * const backup_length
			) {
		auto status{return_status_init()};

		try {
			Expects((conversation_id != nullptr)
					&& (conversation_id_length == CONVERSATION_ID_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			//find the conversation
			Molch::User *user{nullptr};
			Molch::Key<CONVERSATION_ID_SIZE,KeyType::Key> conversation_id_key;
			conversation_id_key.set({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});
			auto conversation{users->findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Couldn't find conversation."};
			}

			user->conversations().remove(conversation_id_key);

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
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * List the conversations of a user.
	 *
	 * Returns the number of conversations and a list of conversations for a given user.
	 * (all the conversation ids in one big list).
	 *
	 * Don't forget to free conversation_list after use.
	 *
	 * Don't forget to destroy the return status with return_status_destroy_errors()
	 * if an error has occurred.
	 */
	return_status molch_list_conversations(
			//outputs
			unsigned char ** const conversation_list,
			size_t * const conversation_list_length,
			size_t * const number,
			//inputs
			const unsigned char * const user_public_master_key,
			const size_t user_public_master_key_length) {
		auto status{return_status_init()};

		try {
			if (conversation_list != nullptr) {
				*conversation_list = nullptr;
			}

			Expects((user_public_master_key != nullptr)
					&& (conversation_list != nullptr)
					&& (conversation_list_length != nullptr)
					&& (number != nullptr)
					&& (user_public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			PublicSigningKey user_public_master_key_key;
			user_public_master_key_key.set({uchar_to_byte(user_public_master_key), PUBLIC_MASTER_KEY_SIZE});
			auto user{users->find(user_public_master_key_key)};
			if (user == nullptr) {
				throw Exception{status_type::NOT_FOUND, "No user found for the given public identity."};
			}

			auto conversation_list_buffer{user->conversations().list()};
			if (conversation_list_buffer.isNone()) {
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
				malloced_conversation_list.cloneFrom(conversation_list_buffer);
				*conversation_list_length = malloced_conversation_list.size();
				*conversation_list = byte_to_uchar(malloced_conversation_list.release());
			}
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
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

	/*
	 * Print a return status into a nice looking error message.
	 *
	 * Don't forget to free the output after use.
	 */
	char *molch_print_status(size_t * const output_length, return_status status) {
		if (output_length == nullptr) {
			return nullptr;
		}

		auto printed{return_status_print(status)};
		*output_length = printed.size();
		return printed.data();
	}

	/*
	 * Get a string describing the return status type.
	 *
	 * (return_status.status)
	 */
	const char *molch_print_status_type(status_type type) {
		return return_status_get_name(type);
	}

	/*
	 * Destroy a return status (only needs to be called if there was an error).
	 */
	void molch_destroy_return_status(return_status * const status) {
		if (status == nullptr) {
			return;
		}

		return_status_destroy_errors(*status);
	}

	/*
	 * Serialize a conversation.
	 *
	 * Don't forget to free the output after use.
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occurred.
	 */
	return_status molch_conversation_export(
			//output
			unsigned char ** const backup,
			size_t * const backup_length,
			//input
			const unsigned char * const conversation_id,
			const size_t conversation_id_length) {
		auto status{return_status_init()};

		try {
			Expects(
					(backup != nullptr)
					&& (backup_length != nullptr)
					&& (conversation_id != nullptr)
					&& (conversation_id_length == CONVERSATION_ID_SIZE));

			ProtobufCEncryptedBackup encrypted_backup_struct;
			encrypted_backup__init(&encrypted_backup_struct);

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			if ((global_backup_key == nullptr) || (global_backup_key->size() != BACKUP_KEY_SIZE)) {
				throw Exception{status_type::INCORRECT_DATA, "No backup key found."};
			}

			//find the conversation
			Molch::User *user{nullptr};
			Molch::Key<CONVERSATION_ID_SIZE,KeyType::Key> conversation_id_key;
			conversation_id_key.set({uchar_to_byte(conversation_id), CONVERSATION_ID_SIZE});
			auto conversation{users->findConversation(user, conversation_id_key)};
			if (conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Failed to find the conversation."};
			}

			//export the conversation
			ProtobufPool pool;
			auto conversation_struct{conversation->exportProtobuf(pool)};

			//pack the struct
			auto conversation_size{conversation__get_packed_size(conversation_struct)};
			auto conversation_buffer_content{pool.allocate<gsl::byte>(conversation_size)};
			span<gsl::byte> conversation_buffer{conversation_buffer_content, conversation_size};
			conversation__pack(conversation_struct, byte_to_uchar(conversation_buffer.data()));

			//generate the nonce
			Buffer backup_nonce{BACKUP_NONCE_SIZE, 0};
			backup_nonce.fillRandom(BACKUP_NONCE_SIZE);

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
				backup_buffer.setSize(0);
				throw Exception{status_type::ENCRYPT_ERROR, "Failed to enrypt conversation state."};
			}

			//fill in the encrypted backup struct
			//metadata
			encrypted_backup_struct.backup_version = 0;
			encrypted_backup_struct.has_backup_type = true;
			encrypted_backup_struct.backup_type = ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP;
			//nonce
			encrypted_backup_struct.has_encrypted_backup_nonce = true;
			encrypted_backup_struct.encrypted_backup_nonce.data = byte_to_uchar(backup_nonce.data());
			encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce.size();
			//encrypted backup
			encrypted_backup_struct.has_encrypted_backup = true;
			encrypted_backup_struct.encrypted_backup.data = byte_to_uchar(backup_buffer.data());
			encrypted_backup_struct.encrypted_backup.len = backup_buffer.size();

			//now pack the entire backup
			const auto encrypted_backup_size{encrypted_backup__get_packed_size(&encrypted_backup_struct)};
			MallocBuffer malloced_encrypted_backup{encrypted_backup_size, 0};
			malloced_encrypted_backup.setSize(encrypted_backup__pack(&encrypted_backup_struct, byte_to_uchar(malloced_encrypted_backup.data())));
			if (malloced_encrypted_backup.size() != encrypted_backup_size) {
				throw Exception{status_type::PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation."};
			}
			*backup_length = malloced_encrypted_backup.size();
			*backup = byte_to_uchar(malloced_encrypted_backup.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		on_error {
			if ((backup != nullptr) && (*backup != nullptr)) {
				free(*backup);
				*backup = nullptr;
			}
			if (backup_length != nullptr) {
				*backup_length = 0;
			}
		}

		return status;
	}

	/*
	 * Import a conversation from a backup (overwrites the current one if it exists).
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occurred.
	 */
	return_status molch_conversation_import(
			//output
			unsigned char * new_backup_key,
			const size_t new_backup_key_length,
			//inputs
			const unsigned char * const backup,
			const size_t backup_length,
			const unsigned char * backup_key,
			const size_t backup_key_length) {
		auto status{return_status_init()};

		try {
			Expects((backup != nullptr)
					&& (backup_key != nullptr)
					&& (backup_key_length == BACKUP_KEY_SIZE)
					&& (new_backup_key_length == BACKUP_KEY_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			//unpack the encrypted backup
			auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(encrypted_backup__unpack(&protobuf_c_allocator, backup_length, backup))};
			if (encrypted_backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
			}

			//check the backup
			if (encrypted_backup_struct->backup_version != 0) {
				throw Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
			}
			if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__CONVERSATION_BACKUP)) {
				throw Exception{status_type::INCORRECT_DATA, "Backup is not a conversation backup."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted conversation state."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
			}

			ProtobufPool pool;
			auto decrypted_backup_content{pool.allocate<gsl::byte>(
						encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
			span<gsl::byte> decrypted_backup{
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
			auto pool_protoc_allocator{pool.getProtobufCAllocator()};
			auto conversation_struct{conversation__unpack(&pool_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()))};
			if (conversation_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack conversations protobuf-c."};
			}

			//import the conversation
			ProtobufCConversation conversation{*conversation_struct};
			Molch::User* containing_user{nullptr};
			Molch::Key<CONVERSATION_ID_SIZE,KeyType::Key> conversation_id_key;
			conversation_id_key.set({
					uchar_to_byte(conversation_struct->id.data),
					conversation_struct->id.len});
			auto existing_conversation{users->findConversation(containing_user, conversation_id_key)};
			if (existing_conversation == nullptr) {
				throw Exception{status_type::NOT_FOUND, "Containing store not found."};
			}

			containing_user->conversations().add(std::move(conversation));

			//update the backup key
			auto status{molch_update_backup_key(new_backup_key, new_backup_key_length)};
			on_error {
				throw Exception{status_type::KEYGENERATION_FAILED, "Failed to update backup key."};
			}
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * Serialise molch's internal state. The output is encrypted with the backup key.
	 *
	 * Don't forget to free the output after use.
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occured.
	 */
	return_status molch_export(
			unsigned char ** const backup,
			size_t *backup_length) {
		auto status{return_status_init()};

		try {
			Expects((backup != nullptr) && (backup_length != nullptr));

			GlobalBackupKeyUnlocker unlocker;
			if ((global_backup_key == nullptr) || global_backup_key->empty) {
				throw Exception{status_type::INCORRECT_DATA, "No backup key found."};
			}

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			ProtobufPool pool;
			auto backup_struct{pool.allocate<ProtobufCBackup>(1)};
			backup__init(backup_struct);

			//export the conversation
			auto exported_users{users->exportProtobuf(pool)};
			backup_struct->users = exported_users.data();
			backup_struct->n_users = exported_users.size();

			//pack the struct
			auto backup_struct_size{backup__get_packed_size(backup_struct)};
			auto users_buffer_content{pool.allocate<gsl::byte>(backup_struct_size)};
			span<gsl::byte> users_buffer{users_buffer_content, backup_struct_size};
			backup__pack(backup_struct, byte_to_uchar(users_buffer.data()));

			//generate the nonce
			Buffer backup_nonce{BACKUP_NONCE_SIZE, 0};
			backup_nonce.fillRandom(BACKUP_NONCE_SIZE);

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
			encrypted_backup__init(&encrypted_backup_struct);
			//metadata
			encrypted_backup_struct.backup_version = 0;
			encrypted_backup_struct.has_backup_type = true;
			encrypted_backup_struct.backup_type = ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP;
			//nonce
			encrypted_backup_struct.has_encrypted_backup_nonce = true;
			encrypted_backup_struct.encrypted_backup_nonce.data = byte_to_uchar(backup_nonce.data());
			encrypted_backup_struct.encrypted_backup_nonce.len = backup_nonce.size();
			//encrypted backup
			encrypted_backup_struct.has_encrypted_backup = true;
			encrypted_backup_struct.encrypted_backup.data = byte_to_uchar(backup_buffer.data());
			encrypted_backup_struct.encrypted_backup.len = backup_buffer.size();

			//now pack the entire backup
			const auto encrypted_backup_size{encrypted_backup__get_packed_size(&encrypted_backup_struct)};
			MallocBuffer malloced_encrypted_backup{encrypted_backup_size, 0};
			malloced_encrypted_backup.setSize(encrypted_backup__pack(&encrypted_backup_struct, byte_to_uchar(malloced_encrypted_backup.data())));
			if (malloced_encrypted_backup.size() != encrypted_backup_size) {
				throw Exception{status_type::PROTOBUF_PACK_ERROR, "Failed to pack encrypted conversation."};
			}
			*backup_length = malloced_encrypted_backup.size();
			*backup = byte_to_uchar(malloced_encrypted_backup.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		on_error {
			if ((backup != nullptr) && (*backup != nullptr)) {
				free(*backup);
				*backup = nullptr;
			}
			if (backup_length != nullptr) {
				*backup_length = 0;
			}
		}

		return status;
	}

	/*
	 * Import molch's internal state from a backup (overwrites the current state)
	 * and generates a new backup key.
	 *
	 * The backup key is needed to decrypt the backup.
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occured.
	 */
	return_status molch_import(
			//output
			unsigned char * const new_backup_key, //BACKUP_KEY_SIZE, can be the same pointer as the backup key
			const size_t new_backup_key_length,
			//inputs
			unsigned char * const backup,
			const size_t backup_length,
			const unsigned char * const backup_key, //BACKUP_KEY_SIZE
			const size_t backup_key_length
			) {
		auto status{return_status_init()};

		try {
			Expects((backup != nullptr)
					&& (backup_key != nullptr)
					&& (backup_key_length == BACKUP_KEY_SIZE)
					&& (new_backup_key_length == BACKUP_KEY_SIZE));

			if (!users) {
				Molch::sodium_init();
			}

			//unpack the encrypted backup
			auto encrypted_backup_struct{std::unique_ptr<ProtobufCEncryptedBackup,EncryptedBackupDeleter>(encrypted_backup__unpack(&protobuf_c_allocator, backup_length, backup))};
			if (encrypted_backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack encrypted backup from protobuf."};
			}

			//check the backup
			if (encrypted_backup_struct->backup_version != 0) {
				throw Exception{status_type::INCORRECT_DATA, "Incompatible backup."};
			}
			if (!encrypted_backup_struct->has_backup_type || (encrypted_backup_struct->backup_type != ENCRYPTED_BACKUP__BACKUP_TYPE__FULL_BACKUP)) {
				throw Exception{status_type::INCORRECT_DATA, "Backup is not a full backup."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup || (encrypted_backup_struct->encrypted_backup.len < crypto_secretbox_MACBYTES)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the encrypted state."};
			}
			if (!encrypted_backup_struct->has_encrypted_backup_nonce || (encrypted_backup_struct->encrypted_backup_nonce.len != BACKUP_NONCE_SIZE)) {
				throw Exception{status_type::PROTOBUF_MISSING_ERROR, "The backup is missing the nonce."};
			}

			ProtobufPool pool;
			auto decrypted_backup_content{pool.allocate<gsl::byte>(
					encrypted_backup_struct->encrypted_backup.len - crypto_secretbox_MACBYTES)};
			span<gsl::byte> decrypted_backup{
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
			auto pool_protoc_allocator{pool.getProtobufCAllocator()};
			auto backup_struct{backup__unpack(&pool_protoc_allocator, decrypted_backup.size(), byte_to_uchar(decrypted_backup.data()))};
			if (backup_struct == nullptr) {
				throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack backups protobuf-c."};
			}

			//import the user store
			auto store{std::make_unique<UserStore>(span<ProtobufCUser*>{backup_struct->users, backup_struct->n_users})};

			//update the backup key
			auto status{molch_update_backup_key(new_backup_key, new_backup_key_length)};
			on_error {
				throw Exception{status};
			}

			//everyting worked, switch to the new user store
			users.reset(store.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * Get a signed list of prekeys for a given user.
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occured.
	 */
	return_status molch_get_prekey_list(
			//output
			unsigned char ** const prekey_list,  //free after use
			size_t * const prekey_list_length,
			//input
			unsigned char * const public_master_key,
			const size_t public_master_key_length) {
		auto status{return_status_init()};

		try {
			Expects((public_master_key != nullptr)
					&& (prekey_list != nullptr)
					&& (prekey_list_length != nullptr)
					&& (public_master_key_length == PUBLIC_MASTER_KEY_SIZE));

			if (!users) {
				throw Exception{status_type::INIT_ERROR, "Molch hasn't been initialized yet."};
			}

			PublicSigningKey public_signing_key_key;
			public_signing_key_key.set({
					uchar_to_byte(public_master_key),
					PUBLIC_MASTER_KEY_SIZE});
			auto prekey_list_buffer{create_prekey_list(public_signing_key_key)};
			MallocBuffer malloced_prekey_list{prekey_list_buffer.size(), 0};
			malloced_prekey_list.cloneFrom(prekey_list_buffer);
			*prekey_list_length = malloced_prekey_list.size();
			*prekey_list = byte_to_uchar(malloced_prekey_list.release());
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
	}

	/*
	 * Generate and return a new key for encrypting the exported library state.
	 *
	 * Don't forget to destroy the return status with molch_destroy_return_status()
	 * if an error has occured.
	 */
	return_status molch_update_backup_key(
			unsigned char * const new_key, //output, BACKUP_KEY_SIZE
			const size_t new_key_length) {
		auto status{return_status_init()};

		try {
			Expects((new_key != nullptr) && (new_key_length == BACKUP_KEY_SIZE));

			if (!users) {
				Molch::sodium_init();
				users = std::make_unique<UserStore>();
			}

			// create a backup key buffer if it doesnt exist already
			if (global_backup_key == nullptr) {
				global_backup_key = std::unique_ptr<BackupKey,SodiumDeleter<BackupKey>>(sodium_malloc<BackupKey>(1));
				new (global_backup_key.get()) BackupKey();
			}

			//make the content of the backup key writable
			GlobalBackupKeyWriteUnlocker unlocker;

			global_backup_key->fillRandom();

			global_backup_key->copyTo({uchar_to_byte(new_key), BACKUP_KEY_SIZE});
		} catch (const Exception& exception) {
			status = exception.toReturnStatus();
			goto cleanup;
		} catch (const std::exception& exception) {
			THROW(status_type::EXCEPTION, exception.what());
		}

	cleanup:
		return status;
}
