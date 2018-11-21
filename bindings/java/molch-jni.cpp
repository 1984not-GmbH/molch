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

#include <molch.h>
#include <molch/constants.h>

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

	extern "C" JNIEXPORT auto JNICALL Java_de_nineteen_eighty_four_not_molch_Molch_createUser(
			JNIEnv *environment,
			[[maybe_unused]] jclass,
			[[maybe_unused]] jboolean create_backup_jboolean,
			[[maybe_unused]] jobject random_spice_optional_jobject) -> jobject {
		const auto CreateUserResult_class = environment->FindClass("de/nineteen/eighty/four/not/molch/Molch$CreateUserResult");
		if (CreateUserResult_class == nullptr) {
			return nullptr;
		}
		const auto CreateUserResult_Constructor = environment->GetMethodID(CreateUserResult_class, "<init>", "()V");
		if (CreateUserResult_Constructor == nullptr) {
			return nullptr;
		}

		return environment->NewObject(CreateUserResult_class, CreateUserResult_Constructor);
	}
}
