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

#define INFO_PUB_KEY_LEN 5
#define INFO_PRE_KEYS_LENGTH 5

namespace Molch::JNI {

	template <typename Container>
	auto operator+=(ByteVector& vector, const Container& container) -> void {
		vector.insert(std::end(vector), std::begin(container), std::end(container));
	}

	template <size_t array_length>
	[[nodiscard]] auto put_length_in_last_two_bytes(ByteArray<array_length>& array, size_t length) -> bool {
		if (length > std::numeric_limits<uint16_t>::max()) {
			return false;
		}

		// little endian
		array[std::size(array) - 2] = static_cast<unsigned char>(length bitand 0xFFU);
		array[std::size(array) - 1] = static_cast<unsigned char>((length >> 8U) bitand 0xFFU);

		return true;
	}

	template <size_t array_length>
	auto get_length_from_last_two_byes(const ByteArray<array_length>& array) -> size_t {
		static_assert(array_length >= 2);

		const auto first_byte = array[std::size(array) - 2];
		const auto second_byte = array[std::size(array) - 1];

		// little endian
		return first_byte + (second_byte << 8U);
	}

	auto getvCardInfoAvatar(
	        const ByteArray<PUBLIC_MASTER_KEY_SIZE>& public_identity_key,
			const ByteVector& prekey_list,
			const ByteVector& avatar_data) -> std::optional<ByteVector> {
		auto public_key_info = ByteArray<INFO_PUB_KEY_LEN>{42, 0, 42, 0, 42};
		if (not put_length_in_last_two_bytes(public_key_info, std::size(public_identity_key))) {
			return std::nullopt;
		}
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar: ", "%zu;", std::size(public_identity_key));)

		auto prekey_list_info = ByteArray<INFO_PRE_KEYS_LENGTH>{0, 42, 0, 42, 0};
		if (not put_length_in_last_two_bytes(prekey_list_info, std::size(prekey_list))) {
			return std::nullopt;
		}
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%zu;", std::size(prekey_list));)

		auto new_vcard = ByteVector();
		new_vcard += public_key_info;
		new_vcard += public_identity_key;
		new_vcard += prekey_list_info;
		new_vcard += prekey_list;
		new_vcard += avatar_data;
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar: ", "%zu;", std::size(new_vcard));)

		return new_vcard;
	}

	auto getvCardPubKey(const ByteVector& avatar_data) -> std::optional<ByteArray<PUBLIC_MASTER_KEY_SIZE>> {
		auto public_key_info = ByteArray<INFO_PUB_KEY_LEN>{42, 0, 42, 0, 42};

		if (std::size(avatar_data) < std::size(public_key_info)) {
			return std::nullopt;
		}

		std::copy(std::begin(avatar_data), std::end(avatar_data), std::begin(public_key_info));
		if (get_length_from_last_two_byes(public_key_info) != PUBLIC_MASTER_KEY_SIZE) {
			return std::nullopt;
		}
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%zu;", PUBLIC_MASTER_KEY_SIZE);)
		auto public_key = ByteArray<PUBLIC_MASTER_KEY_SIZE>();
		std::copy(
				std::begin(avatar_data) + std::size(public_key_info),
				std::begin(avatar_data) + std::size(public_key_info) + std::size(public_key),
				std::begin(public_key));

		return public_key;
	}

	auto getvCardPreKey(const ByteVector& avatar_data) -> std::optional<ByteVector> {
		auto public_key_info = ByteArray<INFO_PUB_KEY_LEN>{42, 0, 42, 0, 42};
		auto prekey_list_info = ByteArray<INFO_PRE_KEYS_LENGTH>{0, 42, 0, 42, 0};

		const auto prekey_list_info_offset = std::size(public_key_info) + PUBLIC_MASTER_KEY_SIZE;
		const auto prekey_list_offset = prekey_list_info_offset + std::size(prekey_list_info);
		if (std::size(avatar_data) < prekey_list_offset) {
			return std::nullopt;
		}

		std::copy(std::begin(avatar_data), std::end(avatar_data), std::begin(public_key_info));
		if (get_length_from_last_two_byes(public_key_info) != PUBLIC_MASTER_KEY_SIZE) {
			return std::nullopt;
		}

		std::copy(
				std::begin(avatar_data) + prekey_list_info_offset,
				std::begin(avatar_data) + prekey_list_info_offset + std::size(prekey_list_info),
				std::begin(prekey_list_info));
		const auto prekey_list_length = get_length_from_last_two_byes(prekey_list_info);
		if ((std::size(avatar_data) - prekey_list_offset) < prekey_list_length) {
			return std::nullopt;
		}

		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys: ", "%zu; %zu ", prekey_list_length, PUBLIC_MASTER_KEY_SIZE);)
		auto prekey_list = ByteVector(prekey_list_length, '\0');
		std::copy(
				std::begin(avatar_data) + prekey_list_offset,
				std::begin(avatar_data) + prekey_list_offset + prekey_list_length,
				std::begin(prekey_list));

		return prekey_list;
	}
}
