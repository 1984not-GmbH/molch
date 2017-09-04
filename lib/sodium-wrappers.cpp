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

	void crypto_sign_keypair(const span<gsl::byte> public_key, const span<gsl::byte> private_key) {
		Expects((public_key.size() == crypto_sign_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_sign_SECRETKEYBYTES));

		auto status{::crypto_sign_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			throw Exception{status_type::KEYGENERATION_FAILED, "Failed to generate crypto_sign keypair."};
		}

	}
	void crypto_sign_seed_keypair(const span<gsl::byte> public_key, const span<gsl::byte> private_key, const span<const gsl::byte> seed) {
		Expects((public_key.size() == crypto_sign_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_sign_SECRETKEYBYTES)
				&& (seed.size() == crypto_sign_SEEDBYTES));

		auto status{::crypto_sign_seed_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()),
				byte_to_uchar(seed.data()))};
		if (status != 0) {
			throw Exception{status_type::KEYGENERATION_FAILED, "Failed to generate crypto_sign keypair from seed."};
		}
	}

	void crypto_generichash(const span<gsl::byte> output, const span<const gsl::byte> input, const span<const gsl::byte> key) {
		Expects((output.size() >= crypto_generichash_BYTES_MIN)
				&& (output.size() <= crypto_generichash_BYTES_MAX)
				&& (key.empty()
					|| ((key.size() >= crypto_generichash_KEYBYTES_MIN)
						&& (key.size() <= crypto_generichash_KEYBYTES_MAX))));

		auto status{::crypto_generichash(
				byte_to_uchar(output.data()), output.size(),
				byte_to_uchar(input.data()), input.size(),
				byte_to_uchar(key.data()), key.size())};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to hash data."};
		}
	}

	CryptoGenerichash::CryptoGenerichash(const span<const gsl::byte> key, size_t output_length)  :
			output_length{output_length} {
		Expects((output_length >= crypto_generichash_BYTES_MIN)
				&& (output_length <= crypto_generichash_BYTES_MAX)
				&& (key.empty()
					|| ((key.size() >= crypto_generichash_KEYBYTES_MIN)
						&& (key.size() <= crypto_generichash_KEYBYTES_MAX))));

		auto status{::crypto_generichash_init(
				&this->state,
				byte_to_uchar(key.data()), key.size(),
				output_length)};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to initialize generichash state."};
		}
	}

	void CryptoGenerichash::update(const span<const gsl::byte> input) {
		auto status{::crypto_generichash_update(
				&this->state,
				byte_to_uchar(input.data()), input.size())};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to update generichash state."};
		}
	}

	void CryptoGenerichash::final(const span<gsl::byte> output) {
		Expects(output.size() == this->output_length);

		auto status{::crypto_generichash_final(
				&this->state,
				byte_to_uchar(output.data()), output.size())};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to finish generichash."};
		}
	}

	CryptoGenerichash::~CryptoGenerichash() {
		sodium_memzero(&this->state, sizeof(this->state));
	}

	void crypto_generichash_blake2b_salt_personal(
			const span<gsl::byte> output,
			const span<const gsl::byte> input,
			const span<const gsl::byte> key,
			const span<const gsl::byte> salt,
			const span<const gsl::byte> personal) {
		Expects((output.size() >= crypto_generichash_blake2b_BYTES_MIN)
				&& (output.size() <= crypto_generichash_blake2b_BYTES_MAX)
				&& (key.size() >= crypto_generichash_blake2b_KEYBYTES_MIN)
				&& (key.size() <= crypto_generichash_blake2b_KEYBYTES_MAX)
				&& (salt.size() == crypto_generichash_blake2b_SALTBYTES)
				&& (personal.size() == crypto_generichash_blake2b_PERSONALBYTES));

		auto status{::crypto_generichash_blake2b_salt_personal(
				byte_to_uchar(output.data()), output.size(),
				byte_to_uchar(input.data()), input.size(),
				byte_to_uchar(key.data()), key.size(),
				byte_to_uchar(salt.data()),
				byte_to_uchar(personal.data()))};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to calculate personal Blake2b hash."};
		}
	}

	void randombytes_buf(const span<gsl::byte> buffer) {
		::randombytes_buf(buffer.data(), buffer.size());
	}

	void crypto_pwhash(
			const span<gsl::byte> output,
			const span<const gsl::byte> password,
			const span<const gsl::byte> salt,
			unsigned long long opslimit,
			size_t memlimit,
			int algorithm) {
		static_assert(crypto_pwhash_PASSWD_MIN == 0, "Minimum password size is not 0.");
		Expects((output.size() >= crypto_pwhash_BYTES_MIN)
				&& (output.size() <= crypto_pwhash_BYTES_MAX)
				//&& (password.size() >= crypto_pwhash_PASSWD_MIN) //see static_assert above
				&& (password.size() <= crypto_pwhash_PASSWD_MAX)
				&& (salt.size() == crypto_pwhash_SALTBYTES));

		auto status{::crypto_pwhash(
				byte_to_uchar(output.data()), output.size(),
				reinterpret_cast<const char*>(password.data()), password.size(),
				byte_to_uchar(salt.data()),
				opslimit,
				memlimit,
				algorithm)};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to derive key from password."};
		}
	}

	void crypto_scalarmult_base(const span<gsl::byte> public_key, const span<const gsl::byte> private_key) {
		Expects((public_key.size() == crypto_scalarmult_BYTES)
				&& (private_key.size() == crypto_scalarmult_SCALARBYTES));

		auto status{::crypto_scalarmult_base(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to calculate public key from private key."};
		}
	}

	void crypto_scalarmult(
			const span<gsl::byte> shared_secret,
			const span<const gsl::byte> our_private_key,
			const span<const gsl::byte> their_public_key) {
		Expects((shared_secret.size() == crypto_scalarmult_BYTES)
				&& (our_private_key.size() == crypto_scalarmult_SCALARBYTES)
				&& (their_public_key.size() == crypto_scalarmult_BYTES));

		auto status{::crypto_scalarmult(
				byte_to_uchar(shared_secret.data()),
				byte_to_uchar(our_private_key.data()),
				byte_to_uchar(their_public_key.data()))};
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to calculate shared secret."};
		}
	}

	bool sodium_is_zero(const span<const gsl::byte> buffer) {
		return ::sodium_is_zero(byte_to_uchar(buffer.data()), buffer.size());
	}

	bool sodium_memcmp(const span<const gsl::byte> b1, const span<const gsl::byte> b2) {
		Expects(b1.size() == b2.size());

		return ::sodium_memcmp(b1.data(), b2.data(), b1.size()) == 0;
	}
}
