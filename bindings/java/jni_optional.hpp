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

#ifndef MOLCH_OPTIONAL_HPP
#define MOLCH_OPTIONAL_HPP

#include "jni_class.hpp"

namespace Molch::JNI {
	class OptionalClass : public Class {
	public:
		explicit OptionalClass(Class&& class_object) : Class(std::move(class_object)) {}

	public:
		static auto Create(JNIEnv& environment) -> std::optional<OptionalClass> {
			auto optional_optional{Class::Create(environment, "java/util/Optional")};
			if (not optional_optional.has_value()) {
				return std::nullopt;
			}
			return OptionalClass(std::move(optional_optional.value()));
		}
	};

	class Optional : public Object {
	private:
		explicit Optional(Object&& object) : Object(std::move(object)) {}

	public:
		static auto empty(JNIEnv& environment) -> std::optional<Optional> {
			auto class_object_optional{OptionalClass::Create(environment)};
			if (not class_object_optional.has_value()) {
				return std::nullopt;
			}
			auto class_object{class_object_optional.value()};

			auto empty_optional{class_object.call<jobject>("empty", "()Ljava/util/Optional;")};
			if (not empty_optional.has_value()) {
				return std::nullopt;
			}
			auto empty{empty_optional.value()};
			if (empty == nullptr) {
				return std::nullopt;
			}

			return Optional::fromJobject(environment, empty);
		}

		static auto fromJobject(JNIEnv& environment, jobject object) -> std::optional<Optional> {
			auto class_object_optional{OptionalClass::Create(environment)};
			if (not class_object_optional.has_value()) {
				return std::nullopt;
			}
			auto class_object{class_object_optional.value()};

			auto optional_optional{Object::Create(environment, class_object, object)};
			if (not optional_optional.has_value()) {
				return std::nullopt;
			}

			return Optional(std::move(optional_optional.value()));
		}
	};
}

#endif //MOLCH_OPTIONAL_HPP
