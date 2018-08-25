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

#ifndef TEST_INLINE_UTILS_HPP
#define TEST_INLINE_UTILS_HPP

inline unsigned char* char_to_uchar(char* pointer) noexcept {
    return reinterpret_cast<unsigned char*>(pointer); //NOLINT
}

inline const unsigned char* char_to_uchar(const char* pointer) noexcept {
    return reinterpret_cast<const unsigned char*>(pointer); //NOLINT
}

inline char* uchar_to_char(unsigned char* pointer) noexcept {
    return reinterpret_cast<char*>(pointer); //NOLINT
}

inline const char* uchar_to_char(const unsigned char* pointer) noexcept {
    return reinterpret_cast<const char*>(pointer); //NOLINT
}

#endif /* TEST_INLINE_UTILS_HPP */
