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
#include "disable-expects.hpp"

namespace Molch {
	result<void> sodium_init() noexcept {
		auto status{::sodium_init()};
		if (status == -1) {
			return Error(status_type::INIT_ERROR, "Failed to initialize libsodium.");
		}

		return outcome::success();
	}

	result<void> crypto_box_keypair(const span<std::byte> public_key, const span<std::byte> private_key) noexcept {
		FulfillOrFail((public_key.size() == crypto_box_PUBLICKEYBYTES) && (private_key.size() == crypto_box_SECRETKEYBYTES));

		auto status{::crypto_box_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			return Error(status_type::KEYGENERATION_FAILED, "Failed to generate crypto_box keypair.");
		}

		return outcome::success();
	}

	result<void> crypto_box_seed_keypair(const span<std::byte> public_key, const span<std::byte> private_key, const span<const std::byte> seed) noexcept {
		FulfillOrFail((public_key.size() == crypto_box_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_box_SECRETKEYBYTES)
				&& (seed.size() == crypto_box_SEEDBYTES));

		auto status{::crypto_box_seed_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()),
				byte_to_uchar(seed.data()))};
		if (status != 0) {
			return Error(status_type::KEYGENERATION_FAILED, "Failed to generate crypto_box keypair from seed.");
		}

		return outcome::success();
	}

	result<void> crypto_sign_keypair(const span<std::byte> public_key, const span<std::byte> private_key) noexcept {
		FulfillOrFail((public_key.size() == crypto_sign_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_sign_SECRETKEYBYTES));

		auto status{::crypto_sign_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			return Error(status_type::KEYGENERATION_FAILED, "Failed to generate crypto_sign keypair.");
		}

		return outcome::success();
	}

	result<void> crypto_sign_seed_keypair(const span<std::byte> public_key, const span<std::byte> private_key, const span<const std::byte> seed) noexcept {
		FulfillOrFail((public_key.size() == crypto_sign_PUBLICKEYBYTES)
				&& (private_key.size() == crypto_sign_SECRETKEYBYTES)
				&& (seed.size() == crypto_sign_SEEDBYTES));

		auto status{::crypto_sign_seed_keypair(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()),
				byte_to_uchar(seed.data()))};
		if (status != 0) {
			return Error(status_type::KEYGENERATION_FAILED, "Failed to generate crypto_sign keypair from seed.");
		}

		return outcome::success();
	}

	result<void> crypto_generichash(const span<std::byte> output, const span<const std::byte> input, const span<const std::byte> key) noexcept {
		FulfillOrFail((output.size() >= crypto_generichash_BYTES_MIN)
				&& (output.size() <= crypto_generichash_BYTES_MAX)
				&& (key.empty()
					|| ((key.size() >= crypto_generichash_KEYBYTES_MIN)
						&& (key.size() <= crypto_generichash_KEYBYTES_MAX))));

		auto status{::crypto_generichash(
				byte_to_uchar(output.data()), output.size(),
				byte_to_uchar(input.data()), input.size(),
				byte_to_uchar(key.data()), key.size())};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to hash data.");
		}

		return outcome::success();
	}

	CryptoGenerichash::CryptoGenerichash(const crypto_generichash_state state, const size_t output_length) noexcept :
	state(state), output_length(output_length)
	{}

	result<CryptoGenerichash> CryptoGenerichash::construct(const span<const std::byte> key, size_t output_length)  {
		FulfillOrFail((output_length >= crypto_generichash_BYTES_MIN)
				&& (output_length <= crypto_generichash_BYTES_MAX)
				&& (key.empty()
					|| ((key.size() >= crypto_generichash_KEYBYTES_MIN)
						&& (key.size() <= crypto_generichash_KEYBYTES_MAX))));

		crypto_generichash_state state;
		auto status{::crypto_generichash_init(
				&state,
				byte_to_uchar(key.data()), key.size(),
				output_length)};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to initialize generichash state.");
		}

		return CryptoGenerichash(state, output_length);
	}

	result<void> CryptoGenerichash::update(const span<const std::byte> input) {
		auto status{::crypto_generichash_update(
				&this->state,
				byte_to_uchar(input.data()), input.size())};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to update generichash state.");
		}

		return outcome::success();
	}

	result<void> CryptoGenerichash::final(const span<std::byte> output) {
		FulfillOrFail(output.size() == this->output_length);

		auto status{::crypto_generichash_final(
				&this->state,
				byte_to_uchar(output.data()), output.size())};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to finish generichash.");
		}

		return outcome::success();
	}

	CryptoGenerichash::~CryptoGenerichash() noexcept {
		sodium_memzero(&this->state, sizeof(this->state));
	}

	result<void> crypto_generichash_blake2b_salt_personal(
			const span<std::byte> output,
			const span<const std::byte> input,
			const span<const std::byte> key,
			const span<const std::byte> salt,
			const span<const std::byte> personal) noexcept {
		FulfillOrFail((output.size() >= crypto_generichash_blake2b_BYTES_MIN)
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
			return Error(status_type::GENERIC_ERROR, "Failed to calculate personal Blake2b hash.");
		}

		return outcome::success();
	}

	void randombytes_buf(const span<std::byte> buffer) noexcept {
		::randombytes_buf(buffer.data(), buffer.size());
	}

	result<void> crypto_pwhash(
			const span<std::byte> output,
			const span<const std::byte> password,
			const span<const std::byte> salt,
			unsigned long long opslimit,
			size_t memlimit,
			int algorithm) noexcept {
		static_assert(crypto_pwhash_PASSWD_MIN == 0, "Minimum password size is not 0.");
		FulfillOrFail((output.size() >= crypto_pwhash_BYTES_MIN)
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
			return Error(status_type::GENERIC_ERROR, "Failed to derive key from password.");
		}

		return outcome::success();
	}

	result<void> crypto_scalarmult_base(const span<std::byte> public_key, const span<const std::byte> private_key) noexcept {
		FulfillOrFail((public_key.size() == crypto_scalarmult_BYTES)
				&& (private_key.size() == crypto_scalarmult_SCALARBYTES));

		auto status{::crypto_scalarmult_base(
				byte_to_uchar(public_key.data()),
				byte_to_uchar(private_key.data()))};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to calculate public key from private key.");
		}

		return outcome::success();
	}

	result<void> crypto_scalarmult(
			const span<std::byte> shared_secret,
			const span<const std::byte> our_private_key,
			const span<const std::byte> their_public_key) noexcept {
		FulfillOrFail((shared_secret.size() == crypto_scalarmult_BYTES)
				&& (our_private_key.size() == crypto_scalarmult_SCALARBYTES)
				&& (their_public_key.size() == crypto_scalarmult_BYTES));

		auto status{::crypto_scalarmult(
				byte_to_uchar(shared_secret.data()),
				byte_to_uchar(our_private_key.data()),
				byte_to_uchar(their_public_key.data()))};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to calculate shared secret.");
		}

		return outcome::success();
	}

	bool sodium_is_zero(const span<const std::byte> buffer) noexcept {
		return ::sodium_is_zero(byte_to_uchar(buffer.data()), buffer.size());
	}

	result<bool> sodium_memcmp(const span<const std::byte> b1, const span<const std::byte> b2) noexcept {
		FulfillOrFail(b1.size() == b2.size());

		return ::sodium_memcmp(b1.data(), b2.data(), b1.size()) == 0;
	}

	result<int> sodium_compare(const span<const std::byte> b1, const span<const std::byte> b2) noexcept {
		FulfillOrFail(b1.size() == b2.size());

		return ::sodium_compare(byte_to_uchar(b1.data()), byte_to_uchar(b2.data()), b1.size());
	}

	void sodium_memzero(const span<std::byte> buffer) noexcept {
		::sodium_memzero(buffer.data(), buffer.size());
	}

	result<void> sodium_bin2hex(const span<char> hex, const span<const std::byte> bin) noexcept {
		FulfillOrFail(hex.size() == (2 * bin.size() + sizeof('\0')));

		::sodium_bin2hex(
				hex.data(), hex.size(),
				byte_to_uchar(bin.data()), bin.size());
		return outcome::success();
	}

	result<void> crypto_secretbox_easy(
			const span<std::byte> ciphertext,
			const span<const std::byte> message,
			const span<const std::byte> nonce,
			const span<const std::byte> key) noexcept {
		FulfillOrFail((ciphertext.size() == (message.size() + crypto_secretbox_MACBYTES))
				&& (nonce.size() == crypto_secretbox_NONCEBYTES)
				&& (key.size() == crypto_secretbox_KEYBYTES));

		auto status{::crypto_secretbox_easy(
				byte_to_uchar(ciphertext.data()),
				byte_to_uchar(message.data()), message.size(),
				byte_to_uchar(nonce.data()),
				byte_to_uchar(key.data()))};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to encrypt message.");
		}

		return outcome::success();
	}

	result<void> crypto_secretbox_open_easy(
			const span<std::byte> message,
			const span<const std::byte> ciphertext,
			const span<const std::byte> nonce,
			const span<const std::byte> key) noexcept {
		FulfillOrFail((ciphertext.size() >= crypto_secretbox_MACBYTES)
				&& (message.size() == (ciphertext.size() - crypto_secretbox_MACBYTES))
				&& (nonce.size() == crypto_secretbox_NONCEBYTES)
				&& (key.size() == crypto_secretbox_KEYBYTES));

		auto status{::crypto_secretbox_open_easy(
				byte_to_uchar(message.data()),
				byte_to_uchar(ciphertext.data()), ciphertext.size(),
				byte_to_uchar(nonce.data()),
				byte_to_uchar(key.data()))};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to decrypt message.");
		}

		return outcome::success();
	}

	result<void> crypto_sign(
			const span<std::byte> signed_message,
			const span<const std::byte> message,
			const span<const std::byte> signing_key) noexcept {
		FulfillOrFail((signed_message.size() == (message.size() + crypto_sign_BYTES))
				&& (signing_key.size() == crypto_sign_SECRETKEYBYTES));

		auto status{::crypto_sign(
				byte_to_uchar(signed_message.data()), nullptr,
				byte_to_uchar(message.data()), message.size(),
				byte_to_uchar(signing_key.data()))};
		if (status != 0) {
			return Error(status_type::SIGN_ERROR, "Failed to sign message.");
		}

		return outcome::success();
	}

	result<void> crypto_sign_open(
			const span<std::byte> verified_message,
			const span<const std::byte> signed_message,
			const span<const std::byte> signing_key) noexcept {
		FulfillOrFail((signed_message.size() >= crypto_sign_BYTES)
				&& (verified_message.size() == (signed_message.size() - crypto_sign_BYTES))
				&& (signing_key.size() == crypto_sign_PUBLICKEYBYTES));

		auto status{::crypto_sign_open(
				byte_to_uchar(verified_message.data()), nullptr,
				byte_to_uchar(signed_message.data()), signed_message.size(),
				byte_to_uchar(signing_key.data()))};
		if (status != 0) {
			return Error(status_type::VERIFICATION_FAILED, "Failed to verify signed message.");
		}

		return outcome::success();
	}

	result<void> sodium_mprotect_noaccess(void *pointer) noexcept {
		auto status{::sodium_mprotect_noaccess(pointer)};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to lock memory.");
		}

		return outcome::success();
	}

	result<void> sodium_mprotect_readonly(void *pointer) noexcept {
		auto status{::sodium_mprotect_readonly(pointer)};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to make memory readonly.");
		}

		return outcome::success();
	}

	result<void> sodium_mprotect_readwrite(void *pointer) noexcept {
		auto status{::sodium_mprotect_readwrite(pointer)};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to make memory readwrite.");
		}

		return outcome::success();
	}

	result<span<std::byte>> sodium_pad(span<std::byte> buffer, const size_t unpadded_length, const size_t blocksize) noexcept {
		FulfillOrFail((unpadded_length < buffer.size()) && (blocksize <= buffer.size()));

		size_t padded_length{0};
		auto status{::sodium_pad(
				&padded_length,
				byte_to_uchar(buffer.data()),
				unpadded_length,
				blocksize,
				buffer.size())};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to pad buffer.");
		}

		return {buffer.data(), padded_length};
	}

	result<span<std::byte>> sodium_unpad(span<std::byte> buffer, const size_t blocksize) noexcept {
		FulfillOrFail(blocksize <= buffer.size());

		size_t unpadded_length{0};
		auto status{::sodium_unpad(
				&unpadded_length,
				byte_to_uchar(buffer.data()),
				buffer.size(),
				blocksize)};
		if (status != 0) {
			return Error(status_type::GENERIC_ERROR, "Failed to unpad buffer.");
		}

		return {buffer.data(), unpadded_length};
	}
}
