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

#include "sodium-wrappers.hpp"
#include "molch-exception.hpp"

namespace Molch {
	void sodium_init() {
		auto status{::sodium_init()};
		if (status == -1) {
			throw Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}
	}

	void crypto_box_keypair(const span<gsl::byte> public_key, const span<gsl::byte> private_key) {
		Expects((public_key.size() == crypto_box_PUBLICKEYBYTES) && (private_key.size() == crypto_box_SECRETKEYBYTES));

		auto status{::crypto_box_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			throw Exception{status_type::KEYGENERATION_FAILED, "Failed to generate crypto_box keypair."};
		}
	}

	void crypto_box_seed_keypair(const span<gsl::byte> public_key, const span<gsl::byte> private_key, const span<const gsl::byte> seed) {
		Expects((public_key.size() == crypto_box_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_box_SECRETKEYBYTES)
				&& (seed.size() == crypto_box_SEEDBYTES));

		auto status{::crypto_box_seed_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()),
				byte_to_uchar(seed.data()))};
		if (status != 0) {
			throw Exception{status_type::KEYGENERATION_FAILED, "Failed to generate crypto_box keypair from seed."};
		}
	}
}
