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

#ifndef MOLCH_JNI_CLASS_HPP
#define MOLCH_JNI_CLASS_HPP

#include <optional>
#include <array>

#include "jni_type_traits.hpp"
#include "jni_fields.hpp"
#include "jni_methods.hpp"

namespace Molch::JNI {
	class Class {
	private:
		JNIEnv& environment;
		jclass _class_object{nullptr};

		Class(JNIEnv& environment, jclass class_object) noexcept
				: environment{environment},
				_class_object{class_object} {}

	public:
		static auto Create(JNIEnv& environment, std::string name) noexcept -> std::optional<Class> {
			const auto class_object{environment.FindClass(name.c_str())};
			if (class_object == nullptr) {
				return std::nullopt;
			}

			return Class(environment, class_object);
		}

		auto class_object() const noexcept -> jclass {
			return this->_class_object;
		}

		template <typename Type>
		auto get(std::string name, std::string signature) -> std::optional<Type> {
			const auto field{environment.GetStaticFieldID(_class_object, name.c_str(), signature.c_str())};
			if (field == nullptr) {
				return std::nullopt;
			}

			return get_static_field<Type>(environment, _class_object, field);
		}

		template <typename Type>
		[[nodiscard]] auto set(std::string name, std::string signature, Type value) -> bool {
			const auto field{environment.GetStaticFieldID(_class_object, name.c_str(), signature.c_str())};
			if (field == nullptr) {
				return false;
			}

			set_static_field(environment, _class_object, value);
			return true;
		}

		template <typename Type, typename... Arguments>
		[[nodiscard]] auto call(std::string name, std::string signature, Arguments... arguments) {
			const auto method{environment.GetStaticMethodID(_class_object, name.c_str(), signature.c_str())};
			if (method == nullptr) {
				if constexpr (std::is_same<void,Type>::value) {
					return false;
				} else {
					return std::optional<Type>{};
				}
			}

			if constexpr (std::is_same<void,Type>::value) {
				call_static(environment, _class_object, method, arguments...);
				return true;
			} else {
				return std::optional<Type>{call_static<jobject>(environment, _class_object, method, arguments...)};
			}
		}
	};

	class Object {
	private:
		JNIEnv& environment;
		Class our_class;
		jobject _object{nullptr};

		Object(JNIEnv& environment, Class our_class, jobject object) noexcept
				: environment{environment},
				our_class{our_class},
				_object{object} {}

	public:
		template <typename... ConstructorArguments>
		static auto Create(JNIEnv& environment, Class our_class, std::string constructor_signature, ConstructorArguments... arguments) -> std::optional<Object> {
			const auto constructor{environment.GetMethodID(our_class.class_object(), "<init>", constructor_signature.c_str())};
			if (constructor == nullptr) {
				return std::nullopt;
			}
			const auto object{environment.NewObject(our_class.class_object(), constructor, arguments...)};
			if (object == nullptr) {
				return std::nullopt;
			}

			return Object(environment, our_class, object);
		}

		Object(const Object&) = delete;

		Object(Object&& other) noexcept
				: environment{other.environment},
				our_class{other.our_class},
				_object{other._object} {
			other._object = nullptr;
		}

		template <typename Type>
		auto get(const char*name, const char* signature) const -> std::optional<Type> {
			const auto field_id{environment.GetFieldID(our_class.class_object(), name, signature)};
			if (field_id == nullptr) {
				return std::nullopt;
			}

			return get_field<Type>(environment, _object, field_id);
		}

		template <typename Type>
		[[nodiscard]] auto set(std::string name, std::string signature, Type value) -> bool {
			const auto field_id{environment.GetFieldID(our_class.class_object(), name.c_str(), signature.c_str())};
			if (field_id == nullptr) {
				return false;
			}

			set_field(environment, _object, field_id, value);
			return true;
		}

		auto object() const noexcept -> jobject {
			return this->_object;
		}

		template <typename Type, typename... Arguments>
		[[nodiscard]] auto call(std::string name, std::string signature, Arguments... arguments) {
			const auto method{environment.GetMethodID(our_class.class_object(), name.c_str(), signature.c_str())};
			if (method == nullptr) {
				if constexpr (std::is_same<void,Type>::value) {
					return false;
				} else {
					return std::optional<Type>{};
				}
			}

			if constexpr (std::is_same<void,Type>::value) {
				call(environment, _object, method, arguments...);
				return true;
			} else {
				return std::optional<Type>{call(environment, _object, method, arguments...)};
			}
		}
	};
}

#endif //MOLCH_JNI_CLASS_HPP
