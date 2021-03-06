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

#include "protobuf-arena.hpp"
#include "sodium-wrappers.hpp"

namespace Molch {
	static google::protobuf::ArenaOptions& getArenaOptions() {
		static constexpr size_t block_size{102400};
		static auto initialized{false};
		static google::protobuf::ArenaOptions arena_options;
		if (!initialized) {
			initialized = true;
			arena_options.start_block_size = block_size;
			arena_options.block_alloc = ::sodium_malloc;
			arena_options.block_dealloc = [](void* data, [[maybe_unused]] size_t size) {
				::sodium_free(data);
			};
		}

		return arena_options;
	}

	static void* protobufCAllocate(void* arena, size_t size) {
		const auto elements = [size]() {
			if ((size % sizeof(max_align_t)) == 0) {
				return size / sizeof(max_align_t);
			}

			return (size / sizeof(max_align_t)) + 1;
		}();
		auto pointer{reinterpret_cast<Arena*>(arena)->allocate<max_align_t>(elements)}; //NOLINT

		return reinterpret_cast<void*>(pointer); //NOLINT
	}

	static void protobufCDeallocate([[maybe_unused]] void* arena, [[maybe_unused]] void* pointer) {}

	Arena::Arena() : google::protobuf::Arena(getArenaOptions()) {}

	ProtobufCAllocator Arena::getProtobufCAllocator() {
		return {
			protobufCAllocate,
			protobufCDeallocate,
			reinterpret_cast<void*>(this) //NOLINT
		};
	}
}
