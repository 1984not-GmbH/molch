/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2019 1984not Security GmbH
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

#ifndef LIB_PublicPrekeyList
#define LIB_PublicPrekeyList

#include <vector>

#include "key.hpp"
#include "time.hpp"
#include "protobuf.hpp"

namespace Molch {
	struct PublicPrekey {
		const PublicKey key;
		const seconds expiration_date;

		static auto import(const ProtobufCPublicPrekey& public_prekey_protobuf) noexcept -> result<PublicPrekey>;

		auto isExpired() const noexcept -> bool;
		auto exportProtobuf(Arena& arena) const noexcept -> result<ProtobufCPublicPrekey*>;

		auto operator==(const PublicPrekey& other) const noexcept -> bool;
	};

	struct PublicPrekeyList {
		const std::vector<PublicPrekey> prekeys;

		static auto import(const ProtobufCPrekeyList& prekey_list_protobuf) noexcept -> result<PublicPrekeyList>;

		auto chooseRandom() const noexcept -> result<PublicPrekey>;

		auto exportProtobuf(Arena& arena) const noexcept -> result<ProtobufCPrekeyList*>;

		auto operator==(const PublicPrekeyList& other) const noexcept -> bool;
	};
}

#endif /* LIB_PublicPrekeyList */
