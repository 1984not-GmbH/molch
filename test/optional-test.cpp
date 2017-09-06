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

#include <cstdlib>
#include <iostream>
#include <exception>

#include "../lib/optional.hpp"
#include "../lib/molch-exception.hpp"

using namespace Molch;

static bool destructed{false};

class Test {
	public:
		int number{0};

		Test() = default;
		Test(const Test& test) {
			this->number = test.number;
		}
		Test(Test&& test) {
			this->number = test.number;
			test.number = 0;
		}
		Test(int number) : number{number} {}

		~Test() {
			destructed = true;
		}

		Test& operator=(const Test& test) {
			this->number = test.number;
			return *this;
		}

		Test& operator=(Test&& test) {
			this->number = test.number;
			test.number = 0;
			return *this;
		}
};

int main() {
	try {
		//empty optional
		optional<Test> empty;
		if (empty || empty.has_value()) {
			throw Exception(status_type::INCORRECT_DATA, "empty optional is not empty.");
		}

		bool has_thrown{false};
		try {
			(void)empty.value();
		} catch (const bad_optional_access& exception) {
			has_thrown = true;
		}
		if (!has_thrown) {
			throw Exception(status_type::GENERIC_ERROR, "Didn't throw when accessing data of empty optional.");
		}

		empty.reset();
		if (destructed) {
			throw Exception(status_type::GENERIC_ERROR, "Shouldn't call destructor when resetting empty optional.");
		}

		//const empty optional
		const optional<Test> const_empty;
		if (const_empty || const_empty.has_value()) {
			throw Exception(status_type::INCORRECT_DATA, "empty const optional is not empty.");
		}

		has_thrown = false;
		try {
			(void)const_empty.value();
		} catch (const bad_optional_access& exception) {
			has_thrown = true;
		}
		if (!has_thrown) {
			throw Exception(status_type::GENERIC_ERROR, "Didn't throw when accessing data of empty const optional.");
		}

		//construct optional
		optional<Test> default_emplaced;
		default_emplaced.emplace();
		if (!default_emplaced) {
			throw Exception(status_type::GENERIC_ERROR, "Failed to emplace with default constructor.");
		}
		if ((default_emplaced->number != 0) || ((*default_emplaced).number != 0) || (default_emplaced.value().number != 0)) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to properly emplace with default constructor.");
		}

		optional<Test> emplaced;
		emplaced.emplace(42);
		if (!emplaced) {
			throw Exception(status_type::GENERIC_ERROR, "Failed to emplace.");
		}
		if ((emplaced->number != 42) || ((*emplaced).number != 42) || (emplaced.value().number != 42)) {
			throw Exception(status_type::INCORRECT_DATA, "Failed to properly emplace.");
		}

		//inplace construction
		optional<Test> inplace(in_place_t(), 42);
		if (!inplace) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to construct inplace."};
		}
		if (inplace->number != 42) {
			throw Exception{status_type::INCORRECT_DATA, "Inplace constructed has invalid number"};
		}

		//const inplace construction
		optional<Test> const_inplace(in_place_t(), 42);
		if (!const_inplace) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to construct inplace."};
		}
		if ((const_inplace->number != 42) || ((*const_inplace).number != 42) || (const_inplace.value().number != 42)) {
			throw Exception{status_type::INCORRECT_DATA, "Inplace constructed has invalid number"};
		}

		//test reset
		optional<Test> to_reset(in_place_t(), 42);
		destructed = false;
		to_reset.reset();
		if (!destructed) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to destruct in reset."};
		}
		destructed = false;
		{
			optional<Test> to_destruct(in_place_t(), 42);
		}
		if (!destructed) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to destruct in reset."};
		}
		destructed = false;

		//test copy constructor
		optional<Test> copied_and_moved_from(in_place_t(), 100);
		optional<Test> copied(copied_and_moved_from);
		if (!copied || (copied->number != 100)) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to copy construct optional."};
		}
		//test move constructor
		optional<Test> moved(std::move(copied_and_moved_from));
		if (!moved || (moved->number != 100)) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to move construct optional."};
		}
		if (copied_and_moved_from->number != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to invalidate moved from optional content."};
		}

		//test copy and move constructor with empty optionals
		optional<Test> empty_copied_and_moved_from;
		optional<Test> empty_copied;
		optional<Test> empty_moved;
		if (empty_copied || empty_moved) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to copy or move empty optional."};
		}

		//test copy and move assignment operators
		optional<Test> copy_and_move_assigned_from(in_place_t(), 100);
		optional<Test> copy_assigned;
		copy_assigned = copy_and_move_assigned_from;
		if (!copy_assigned || (copy_assigned->number != 100)) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to copy assign optional."};
		}
		//test move assignment
		optional<Test> move_assigned;
		move_assigned = std::move(copy_and_move_assigned_from);
		if (!move_assigned || (move_assigned->number != 100)) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to move assign optional."};
		}
		if (copy_and_move_assigned_from->number != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to invalidate assignment moved from optional content."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
