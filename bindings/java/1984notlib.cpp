/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 1984not Security GmbH
 * Authors: Bernd Herzmann, Max Bruckner
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

#include <cstring>
#include <algorithm>

#ifdef __ANDROID__
#include <android/log.h>
#define android_only(code) code
#else
#define android_only(code)
#endif

#include "1984notlib.hpp"
#include "molch/constants.h"

#define INFO_DATA_LENGTH 3
#define INFO_PUB_KEY_LEN 5
#define INFO_PRE_KEYS_LENGTH 5

namespace Molch::JNI {

	/*
	 * Determine the current endianness at runtime.
	 */
	static bool endianness_is_little_endian() {
		const uint16_t number = 0x1;
		const unsigned char *const number_pointer = (const unsigned char *) &number;
		return (number_pointer[0] == 0x1);
	}

	auto getvCardInfoAvatar(
	        const std::array<unsigned char,PUBLIC_MASTER_KEY_SIZE>& public_identity_key,
			const ByteVector& prekey_list,
			const ByteVector& avatar_data) -> std::optional<ByteVector> {
		auto public_key_info = std::array<unsigned char,INFO_PUB_KEY_LEN>{42, 0, 42, 0, 42};
		auto prekey_list_info = std::array<unsigned char,INFO_PRE_KEYS_LENGTH>{0, 42, 0, 42, 0};

		// store public key size as 16 bit little endian
		public_key_info[INFO_DATA_LENGTH] = static_cast<unsigned char>(std::size(public_identity_key) bitand 0xFFU);
		public_key_info[INFO_DATA_LENGTH + 1] = static_cast<unsigned char>((std::size(public_identity_key) >> 8U) bitand 0xFFU);
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar: ", "%zu;", std::size(public_identity_key));)

		// store prekey list size as little endian
		if (std::size(prekey_list) > std::numeric_limits<uint16_t>::max()) {
			return std::nullopt;
		}
		prekey_list_info[INFO_DATA_LENGTH] = static_cast<unsigned char>(std::size(prekey_list) bitand 0xFFU);
		prekey_list_info[INFO_DATA_LENGTH + 1] = static_cast<unsigned char>((std::size(prekey_list) >> 8U) bitand 0xFFU);
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%zu;", std::size(prekey_list));)

		auto new_vcard = ByteVector();
		new_vcard.insert(std::end(new_vcard), std::begin(public_key_info), std::end(public_key_info));
		new_vcard.insert(std::end(new_vcard), std::begin(public_identity_key), std::end(public_identity_key));
		new_vcard.insert(std::end(new_vcard), std::begin(prekey_list_info), std::end(prekey_list_info));
		new_vcard.insert(std::end(new_vcard), std::begin(prekey_list), std::end(prekey_list));
		new_vcard.insert(std::end(new_vcard), std::begin(avatar_data), std::end(avatar_data));
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar: ", "%zu;", std::size(new_vcard));)

		return new_vcard;
	}

	auto getvCardPubKey(
			const unsigned char *avatarData,
			const size_t avatarLength,
			unsigned char **newpubKey,
			size_t *retLength) -> int {
		unsigned char infoPubKey[INFO_PUB_KEY_LEN] = {42, 0, 42, 0, 42};

		if (avatarLength > INFO_PUB_KEY_LEN) {
			memcpy(infoPubKey, avatarData, INFO_PUB_KEY_LEN);
			unsigned short tmpLength = 0;
			if (endianness_is_little_endian()) {
				memcpy(&tmpLength, &infoPubKey[INFO_DATA_LENGTH], sizeof(tmpLength));
				android_only(
						__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
			} else {
				//if already big endian, just copy
				android_only(
						__android_log_print(ANDROID_LOG_DEBUG, "getvCardPubKey_big_endian_todo: ", "%d; %zu", tmpLength,
											sizeof(tmpLength));) //BHR:TODO 22032016
			}
			if (tmpLength < SIZE_MAX && tmpLength < (avatarLength + INFO_PUB_KEY_LEN)) {
				*newpubKey = (unsigned char*)malloc(tmpLength);
				memcpy(*newpubKey, &avatarData[INFO_PUB_KEY_LEN], tmpLength);
				*retLength = tmpLength;
			} else {
				return -2;
			}
		} else {
			return -1;
		}
		return 0;
	}

	auto getvCardPreKeys(
			const unsigned char *avatarData,
			const size_t avatarLength,
			unsigned char **newpreKeys,
			size_t *retLength) -> int {
		unsigned char infoPubKey[INFO_PUB_KEY_LEN] = {42, 0, 42, 0, 42};
		unsigned char infoPreKeys[INFO_PRE_KEYS_LENGTH] = {0, 42, 0, 42, 0};

		if (avatarLength > INFO_PRE_KEYS_LENGTH) {
			memcpy(infoPubKey, avatarData, INFO_PUB_KEY_LEN);
			unsigned short tmpLengthPubKey = 0;
			if (endianness_is_little_endian()) {
				memcpy(&tmpLengthPubKey, &infoPubKey[INFO_DATA_LENGTH], sizeof(tmpLengthPubKey));
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;",
												 tmpLengthPubKey);)
			} else {
				//if already big endian, just copy
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys_big_endian_todo: ", "%d;",
												 tmpLengthPubKey);) //BHR:TODO 22032016
			}

			int startPreKeys = INFO_PUB_KEY_LEN + tmpLengthPubKey;
			memcpy(infoPreKeys, avatarData + startPreKeys, INFO_PRE_KEYS_LENGTH);
			unsigned short tmpLength = 0;
			if (endianness_is_little_endian()) {
				memcpy(&tmpLength, &infoPreKeys[INFO_DATA_LENGTH], sizeof(tmpLength));
				android_only(
						__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
			} else {
				//if already big endian, just copy
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys_big_endian_todo: ", "%d;",
												 tmpLength);) //BHR:TODO 22032016
			}
			if (tmpLength < SIZE_MAX && tmpLengthPubKey < SIZE_MAX && tmpLength < avatarLength &&
				tmpLengthPubKey < avatarLength) {
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys: ", "%d; %d ", (int) tmpLength,
												 (int) tmpLengthPubKey);)
				*retLength = tmpLength;
				*newpreKeys = (unsigned char*)malloc(*retLength);
				memcpy(*newpreKeys, &avatarData[INFO_PUB_KEY_LEN + tmpLengthPubKey + INFO_PRE_KEYS_LENGTH], *retLength);
			} else {
				return -2;
			}
		} else {
			return -1;
		}
		return 0;
	}
}
