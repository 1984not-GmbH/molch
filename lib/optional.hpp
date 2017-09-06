/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 Max Bruckner (FSMaxB) <max at maxbruckner dot de>
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

/* \file
 * Simple implementation of a type similar to std::optional until
 * Molch can switch to C++17 and use the real std::optional.
 */

#ifndef LIB_OPTIONAL_HPP
#define LIB_OPTIONAL_HPP

#include <type_traits>
#include <exception>
#include <initializer_list>
#include <utility>

namespace Molch {

	class bad_optional_access : public std::exception {
	public:
		virtual const char* what() const noexcept override;
	};

	struct in_place_t {};

	template <typename T>
	class optional {
	private:
		bool is_valid{false};
		union {
			T member;
		};

	public:
		constexpr optional() noexcept {}
		constexpr optional(const optional& other) {
			if (other) {
				new (&this->member) T(*other);
				this->is_valid = true;
			}
		}
		constexpr optional(optional&& other) {
			if (other) {
				new (&this->member) T(std::move(*other));
				this->is_valid = true;
			}
		}

		template <typename... Args>
		constexpr explicit optional(in_place_t, Args&&... args) {
			new (&this->member) T(args...);
			this->is_valid = true;
		}

		~optional() {
			this->reset();
		}

		optional& operator=(const optional& other) {
			if (!other) {
				this->reset();
				return *this;
			}

			if (this->is_valid) {
				this->member = *other;
				return *this;
			}

			new (&this->member) T(*other);
			this->is_valid = true;
			return *this;
		}

		optional& operator=(optional&& other) {
			if (!other) {
				this->reset();
				return *this;
			}

			if (this->is_valid) {
				this->member = std::move(*other);
				return *this;
			}

			new (&this->member) T(std::move(*other));
			this->is_valid = true;
			return *this;
		}

		constexpr const T* operator->() const {
			if (!is_valid) {
				return nullptr;
			}

			return &this->member;
		}
		constexpr T* operator->() {
			if (!is_valid) { return nullptr;
			}

			return &this->member;
		}
		constexpr const T& operator*() const& {
			return this->member;
		}
		constexpr T& operator*() & {
			return this->member;
		}
		constexpr T&& operator*() && {
			return std::move(this->member);
		}

		constexpr explicit operator bool() const noexcept {
			return this->is_valid;
		}
		constexpr bool has_value() const noexcept {
			return this->is_valid;
		}

		constexpr T& value() & {
			if (!this->is_valid) {
				throw bad_optional_access();
			}

			return this->member;
		}
		constexpr const T& value() const& {
			if (!this->is_valid) {
				throw bad_optional_access();
			}

			return this->member;
		}

		void reset() noexcept {
			if (this->is_valid) {
				this->member.~T();
			}

			this->is_valid = false;
		}

		template <typename... Args>
		T& emplace(Args&&... args) {
			if (this->is_valid) {
				this->reset();
			}

			new (&this->member) T(args...);
			this->is_valid = true;

			return this->member;
		}
	};
}

#endif /* LIB_OPTIONAL_HPP */
