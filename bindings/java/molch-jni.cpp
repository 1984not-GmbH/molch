/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 1984not Security GmbH
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

#include "de_nineteen_eighty_four_not_molch_Molch.h"

#include <type_traits>
#include <iterator>

#include <molch.h>
#include <molch/constants.h>

#include "jni_type_traits.hpp"
#include "jni_array.hpp"
#include "jni_class.hpp"
#include "jni_optional.hpp"

namespace Molch::JNI {
	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_getUserIdSize([[maybe_unused]] JNIEnv *, [[maybe_unused]] jclass) -> jlong {
		return PUBLIC_MASTER_KEY_SIZE;
	}

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_getConversationIdSize([[maybe_unused]] JNIEnv *, [[maybe_unused]] jclass) -> jlong {
		return CONVERSATION_ID_SIZE;
	}

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_getBackupKeySize([[maybe_unused]] JNIEnv *, [[maybe_unused]] jclass) -> jlong {
		return BACKUP_KEY_SIZE;
	}


	template <typename Type>
	class AutoFreePointer {
	public:
		AutoFreePointer() = default;
		AutoFreePointer(Type* pointer) noexcept : pointer{pointer} {}

		AutoFreePointer(const AutoFreePointer&) = delete;
		AutoFreePointer(AutoFreePointer&&) = delete;

		auto get() noexcept -> Type* {
			return pointer;
		}

		auto get() const noexcept -> const Type* {
			return pointer;
		}

		auto meta_pointer() noexcept -> Type** {
			return &pointer;
		}

		~AutoFreePointer() {
			if (pointer != nullptr) {
				free(nullptr);
			}
		}

	private:
		Type* pointer{nullptr};
	};

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_createUser(
			JNIEnv *environment,
			[[maybe_unused]] jclass,
			jbyteArray random_spice_jarray) -> jobject {
		if (environment == nullptr) {
			return nullptr;
		}

		const auto CreateUserResult_optional{Class::Create(*environment, "de/nineteen/eighty/four/not/molch/Molch$CreateUserResult")};
		if (not CreateUserResult_optional.has_value()) {
			return nullptr;
		}
		const auto& CreateUserResult{CreateUserResult_optional.value()};

		// result = new CreateUserResult()
		auto result_optional{Object::Create(*environment, CreateUserResult, "()V")};
		if (not result_optional.has_value()) {
			return nullptr;
		}
		auto& result{result_optional.value()};

		// result.userId = new byte[PUBLIC_MASTER_KEY_SIZE];
		auto userId_array_optional{Array<jbyte>::Create(*environment, PUBLIC_MASTER_KEY_SIZE)};
		if (not userId_array_optional.has_value()) {
			return nullptr;
		}
		auto& userId_array{userId_array_optional.value()};
		if (not result.set("userId", "[B", userId_array.array())) {
			return nullptr;
		}

		// result.backupKey = new byte[BACKUP_KEY_SIZE]
		auto backupKey_array_optional{Array<jbyte>::Create(*environment, BACKUP_KEY_SIZE)};
		if (not backupKey_array_optional.has_value()) {
			return nullptr;
		}
		auto& backupKey_array{backupKey_array_optional.value()};
		if (not result.set("backupKey", "[B", backupKey_array.array())) {
			return nullptr;
		}

		auto random_spice_array_optional{Array<jbyte>::Create(*environment, random_spice_jarray)};
		auto random_spice_pointer{static_cast<unsigned char*>(nullptr)};
		auto random_spice_length{static_cast<size_t>(0)};
		if (random_spice_array_optional.has_value()) {
			auto& random_spice_array{random_spice_array_optional.value()};
			random_spice_pointer = reinterpret_cast<unsigned char*>(std::data(random_spice_array));
			random_spice_length = std::size(random_spice_array);
		}

		auto prekey_list{AutoFreePointer<unsigned char>()};
		auto prekey_list_length{static_cast<size_t>(0)};
		auto backup{AutoFreePointer<unsigned char>()};
		auto backup_length{static_cast<size_t>(0)};
		const auto status = molch_create_user(
				reinterpret_cast<unsigned char*>(std::data(userId_array)),
				std::size(userId_array),
				prekey_list.meta_pointer(),
				&prekey_list_length,
				reinterpret_cast<unsigned char*>(std::data(backupKey_array)),
				std::size(backupKey_array),
				backup.meta_pointer(),
				&backup_length,
				random_spice_pointer,
				random_spice_length);
		if (status.status != status_type::SUCCESS) {
			//TODO: Throw exception
			return nullptr;
		}

		// result.prekey_list = prekey_list
		auto prekey_list_array_optional{Array<jbyte>::Create(*environment, prekey_list_length)};
		if (not prekey_list_array_optional.has_value()) {
			return nullptr;
		}
		auto& prekey_list_array{prekey_list_array_optional.value()};
		std::copy(prekey_list.get(), prekey_list.get() + prekey_list_length, std::data(prekey_list_array));
		if (not result.set("prekeyList", "[B", prekey_list_array.array())) {
			return nullptr;
		}

		// result.backup = backup
		auto backup_array_optional{Array<jbyte>::Create(*environment, backup_length)};
		if (not backup_array_optional.has_value()) {
			return nullptr;
		}
		auto& backup_array{backup_array_optional.value()};
		std::copy(backup.get(), backup.get() + backup_length, std::data(backup_array));
		if (not result.set("backup", "[B", backup_array.array())) {
			return nullptr;
		}

		return result.object();
	}

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_countUsers(
			[[maybe_unused]] JNIEnv*,
			[[maybe_unused]] jclass) -> jlong {
		return static_cast<jlong>(molch_user_count());
	}

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_destroyAllUsers(
			[[maybe_unused]] JNIEnv*,
			[[maybe_unused]] jclass) -> void {
		molch_destroy_all_users();
	}

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_getPrekeyListExpirationDateSeconds(
			JNIEnv *environment,
			[[maybe_unused]] jclass,
			jbyteArray user_id) -> jlongArray {
		static_assert(sizeof(int64_t) == sizeof(jlong));

		const auto user_id_array_optional{Array<jbyte>::Create(*environment, user_id)};
		if (not user_id_array_optional.has_value()) {
			return nullptr;
		}
		const auto& user_id_array{user_id_array_optional.value()};

		auto malloced_expiration_seconds{AutoFreePointer<int64_t>()};
		size_t malloced_expiration_seconds_length{0};
		const auto status{molch_get_prekey_list_expiration_seconds(
				malloced_expiration_seconds.meta_pointer(),
				&malloced_expiration_seconds_length,
				reinterpret_cast<const unsigned char*>(std::data(user_id_array)),
				std::size(user_id_array))};
		if (status.status != status_type::SUCCESS) {
			// TODO: Throw exception!
			return nullptr;
		}

		auto expiration_date_array_optional{Array<jlong>::Create(*environment, malloced_expiration_seconds_length)};
		if (not expiration_date_array_optional.has_value()) {
			return nullptr;
		}
		auto& expiration_date_array{expiration_date_array_optional.value()};

		std::copy(
				malloced_expiration_seconds.get(),
				malloced_expiration_seconds.get() + malloced_expiration_seconds_length,
				std::data(expiration_date_array));


		return expiration_date_array.array();
	}
}
