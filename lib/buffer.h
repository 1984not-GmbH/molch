/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <alloca.h>
#include <stdbool.h>

#ifndef LIB_BUFFER_H
#define LIB_BUFFER_H

typedef struct buffer_t {
	size_t buffer_length;
	size_t content_length;
	bool readonly; //if set, this buffer shouldn't be written to.
	unsigned char *content;
} buffer_t;

/*
 * Initialize a buffer with a given length.
 *
 * This is normally not called directly but via
 * the buffer_create macro.
 */
buffer_t* buffer_init(
		buffer_t * const buffer,
		const size_t buffer_length);

/*
 * Macro to create a new buffer of a given name and length;
 */
#define buffer_create(length) buffer_init(alloca(sizeof(buffer_t) + length), length)

#endif
