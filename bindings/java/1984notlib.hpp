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

#ifndef LIB_1984NOTLIB_H
#define LIB_1984NOTLIB_H

#include <cstddef>
#include <vector>
#include <array>
#include <optional>

#include "molch/constants.h"

namespace Molch::JNI {
	using ByteVector = std::vector<unsigned char>;
	template <size_t length>
	using ByteArray = std::array<unsigned char,length>;

	auto getvCardInfoAvatar(
			const ByteArray<PUBLIC_MASTER_KEY_SIZE>& public_identity_key,
			const ByteVector& prekey_list,
			const ByteVector& avatar_data) -> std::optional<ByteVector>;
	auto getvCardPubKey(const ByteVector& avatar_data) -> std::optional<ByteArray<PUBLIC_MASTER_KEY_SIZE>>;
	auto getvCardPreKey(const ByteVector& avatar_data) -> std::optional<ByteVector>;
}

#endif
