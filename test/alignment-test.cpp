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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../lib/alignment.h"
#include "utils.h"

int main(void) {
	return_status status = return_status_init();

	printf("Alignment of intmax_t: %zu\n", ALIGNMENT_OF(intmax_t));

	printf("Testing next_aligned_address.\n");
	if ((next_aligned_address((void*)3, 4) != (void*)4) || (next_aligned_address((void*)8, 4) != (void*)8)) {
		throw(INCORRECT_DATA, "Didn't calculate the correct next aligned address.");
	}

cleanup:
	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
