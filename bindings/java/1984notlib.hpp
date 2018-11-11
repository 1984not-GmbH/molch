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

namespace Molch::JNI {
	auto getvCardInfoAvatar(
			const unsigned char *public_identity_key,
			const size_t publicLength,
			const unsigned char *preKeyList,
			const size_t preKeysLength,
			const unsigned char *avatarData,
			const size_t avatarLength,
			unsigned char **newVcard,
			size_t *retLength) -> int;
	auto getvCardPubKey(
			const unsigned char *avatarData,
			const size_t avatarLength,
			unsigned char **newpubKey,
			size_t *retLength) -> int;
	auto getvCardPreKeys(
			const unsigned char *avatarData,
			const size_t avatarLength,
			unsigned char **newpubKey,
			size_t *retLength) -> int;
}

#endif
