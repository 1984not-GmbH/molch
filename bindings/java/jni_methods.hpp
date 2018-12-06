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

#ifndef MOLCH_JNI_METHODS_HPP
#define MOLCH_JNI_METHODS_HPP

#include "jni_type_traits.hpp"

namespace Molch::JNI {
	template <typename Type, typename... Arguments>
	auto call(JNIEnv& environment, jobject object, jmethodID method, Arguments... arguments) {
		static_assert(is_java_type<Type>::value, "Type must be a Java type.");

		if constexpr (std::is_same<Type,void>::value) {
			return environment.CallVoidMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jobject>::value) {
			return environment.CallObjectMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.CallBooleanMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.CallByteMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.CallCharMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.CallShortMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.CallIntMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.CallLongMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.CallFloatMethod(object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.CallDoubleMethod(object, method, arguments...);
		}
	}

	template <typename Type, typename... Arguments>
	auto call_static(JNIEnv& environment, jclass class_object, jmethodID method, Arguments... arguments) {
		static_assert(is_java_type<Type>::value, "Type must be a Java type.");

		if constexpr (std::is_same<Type,void>::value) {
			return environment.CallStaticVoidMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jobject>::value) {
			return environment.CallStaticObjectMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.CallStaticBooleanMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.CallStaticByteMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.CallStaticCharMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.CallStaticShortMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.CallStaticIntMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.CallStaticLongMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.CallStaticFloatMethod(class_object, method, arguments...);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.CallStaticDoubleMethod(class_object, method, arguments...);
		}
	}
}

#endif //MOLCH_JNI_METHODS_HPP
