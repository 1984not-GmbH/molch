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

/*! \file
 * Functions and macros to help get the correct memory alignment of types.
 */

#ifndef LIB_ALIGNMENT_H
#define LIB_ALIGNMENT_H

#include <cstddef>

/*!
 * Calculate the next pointer that is aligned to the given
 * alignment.
 *
 * \param pointer
 *   The base pointer from which the next aligned position is
 *   calculated.
 *
 * \param alignment
 *   The alignment to which the pointer should be aligned.
 *
 * \return A pointer that is aligned to alignment.
 */
void *next_aligned_address(void *pointer, size_t alignment);

#endif
