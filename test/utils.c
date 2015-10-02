/*  Molch, an implementation of the axolotl ratchet based on libsodium
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
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "utils.h"

char* get_file_as_string(FILE *file, size_t * const length) {
	char* line = malloc(100);
	if (line == NULL) {
		return NULL;
	}
	char* line_pointer = line;
	size_t lenmax = 100;
	size_t len = lenmax;
	int c;

	while(1) {
		c = fgetc(file);
		if(c == EOF)
			break;

		if(--len == 0) {
			len = lenmax;
			char* line_new = realloc(line_pointer, lenmax *= 2);
			if (line_new == NULL) {
				return NULL;
			}

			line = line_new + (line - line_pointer);
			line_pointer = line_new;
		}

		*line++ = c;
	}
	*line = '\0';
	*length = line - line_pointer; //excluding the closing '\0'

	return line_pointer;
}

void print_hex(const buffer_t * const data) {
	static const int WIDTH = 30;
	//buffer for hex string
	buffer_t *hex = buffer_create(2 * data->content_length + 1, 2 * data->content_length + 1);

	if (sodium_bin2hex((char *)hex->content, 2 * data->content_length + 1, data->content, data->content_length) == NULL) {
		fprintf(stderr, "ERROR: Failed printing hex.\n");
		buffer_clear(hex);
		return;
	}

	for (size_t i = 0; i < 2 * data->content_length; i++) {
		if ((WIDTH != 0) && (i % WIDTH == 0) && (i != 0)) {
			putchar('\n');
		} else if ((i % 2 == 0) && (i != 0)) {
			putchar(' ');
		}
		putchar(hex->content[i]);
	}

	putchar('\n');

	//cleanup
	buffer_clear(hex);
}
