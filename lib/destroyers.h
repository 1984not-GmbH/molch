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

//! \file Common destroyers.

#ifndef LIB_DESTROYERS_H
#define LIB_DESTROYERS_H

#include "buffer.h"

template <typename T>
inline void free_and_null_if_valid(T*& pointer) {
	if (pointer != nullptr) {
		free(pointer);
		pointer = nullptr;
	}
}

template <typename T>
inline void sodium_free_and_null_if_valid(T*& pointer) {
	if (pointer != nullptr) {
		sodium_free(pointer);
		pointer = nullptr;
	}
}

template <typename T>
inline void zeroed_free_and_null_if_valid(T*& pointer) {
	if (pointer != nullptr) {
		zeroed_free(pointer);
		pointer = nullptr;
	}
}

inline void buffer_destroy_and_null_if_valid(Buffer*& buffer) {
	if (buffer != nullptr) {
		buffer->destroy();
		buffer = nullptr;
	}
}

#endif /* LIB_DESTROYERS_H */
