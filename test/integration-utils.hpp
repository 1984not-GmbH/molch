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

#ifndef TEST_INTEGRATION_UTILS_HPP
#define TEST_INTEGRATION_UTILS_HPP

#include <array>
#include <vector>
#include <exception>
#include <fstream>

#include "molch.h"

class BackupKeyArray : public std::array<unsigned char,32> {};
class PublicIdentity : public std::array<unsigned char,32> {};
class ConversationID : public std::array<unsigned char,32> {};

struct Exception : public std::exception {
	Exception(std::string message) : message{message} {}
	std::string message;
	const char* what() const noexcept override {
		return message.data();
	}
};

struct AutoFreeBuffer {
	size_t length{0};
	unsigned char *pointer{nullptr};

	AutoFreeBuffer() = default;
	AutoFreeBuffer(const AutoFreeBuffer&) = delete;
	AutoFreeBuffer(AutoFreeBuffer&&) = delete;
	AutoFreeBuffer& operator=(const AutoFreeBuffer&) = delete;
	AutoFreeBuffer& operator=(AutoFreeBuffer&&) = delete;

	bool empty() const noexcept {
		return length == 0;
	}

	unsigned char *data() noexcept {
		return pointer;
	}

	const unsigned char *data() const noexcept {
		return pointer;
	}

	size_t size() const noexcept {
		return length;
	}

	~AutoFreeBuffer() noexcept {
		if (pointer != nullptr) {
			free(pointer);
		}
	}
};

inline char nible_to_hex(unsigned char nible) {
	nible &= 0xF;

	if ((nible > 0) && (nible < 10)) {
		return static_cast<char>('0' + nible);
	}

	return static_cast<char>('A' + (nible - 10));
}

inline std::string byte_to_hex(const unsigned char byte) {
	auto lower_nible = static_cast<unsigned char>(byte & 0x0F);
	auto upper_nible = static_cast<unsigned char>((byte & 0xF0) >> 4);

	std::string hex;
	hex.push_back(nible_to_hex(upper_nible));
	hex.push_back(nible_to_hex(lower_nible));

	return hex;
}

template <typename BufferType>
inline std::string buffer_to_hex(const BufferType& buffer) {
	std::string hex;
	hex.reserve(std::size(buffer) * 2);
	for (const unsigned char byte : buffer) {
		hex += byte_to_hex(byte);
	}

	return hex;
}

std::vector<unsigned char> read_file(const std::string name);

template <typename BufferType>
inline void write_to_file(const BufferType& content, std::string name) {
	std::ofstream filestream(name, std::ios_base::binary);
	if (!filestream.is_open()) {
		throw Exception("Failed to open file '" + name + "' for writing.");
	}

	if (content.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
		throw Exception("File content is to large for the file stream.");
	}

	filestream.write(reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
}
#endif /* TEST_INTEGRATION_UTILS_HPP */
