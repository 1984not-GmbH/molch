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

#ifndef MOLCH_JNI_TYPE_TRANSFORMATIONS_HPP
#define MOLCH_JNI_TYPE_TRANSFORMATIONS_HPP

#include "jni_type_traits.hpp"

namespace Molch::JNI {
	[[maybe_unused]] constexpr auto test_that_jni_types_are_proper() -> void {
		static_assert(not std::is_same<jshort,jchar>::value, "jshort and jchar must be different types");
		static_assert(not std::is_same<jshort, jboolean>::value, "jshort and jboolean must be different types");
		static_assert(not std::is_same<jshort, jint>::value, "jshort and jint must be different types");
		static_assert(not std::is_same<jint,jboolean>::value, "jint and jboolean must be different types");
		static_assert(not std::is_same<jint,jchar>::value, "jint and jchar must be different types");
		static_assert(not std::is_same<jint,jshort>::value, "jint and jshort must be different types");
		static_assert(not std::is_same<jint,jlong>::value, "jint and jlong must be different types");
		static_assert(not std::is_same<jfloat,jdouble>::value, "jfloat and jdouble must be different types");
	}

	template <typename ElementType>
	constexpr auto array_type_from_element() {
		static_assert(is_value_primitive<ElementType>::value or is_object<ElementType>::value, "ElementType must be a primitive java value or an object.");

		if constexpr (is_object<ElementType>::value) {
			return static_cast<jobjectArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jboolean>::value) {
			return static_cast<jbooleanArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jbyte>::value) {
			return static_cast<jbyteArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jchar>::value) {
			return static_cast<jcharArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jshort>::value) {
			return static_cast<jshortArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jint>::value) {
			return static_cast<jintArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jlong>::value) {
			return static_cast<jlongArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jfloat>::value) {
			return static_cast<jfloatArray>(nullptr);
		}

		if constexpr (std::is_same<ElementType,jdouble>::value) {
			return static_cast<jdoubleArray>(nullptr);
		}
	}

	[[maybe_unused]] constexpr auto test_array_type_from_element() {
		static_assert(std::is_same<jbooleanArray,decltype(array_type_from_element<jboolean>())>::value, "array_type_from_element failed to convert jboolean -> jbooleanArray");
		static_assert(std::is_same<jbyteArray,decltype(array_type_from_element<jbyte>())>::value, "array_type_from_element failed to convert jbyte -> jbyteArray");
		static_assert(std::is_same<jcharArray,decltype(array_type_from_element<jchar>())>::value, "array_type_from_element failed to convert jchar -> jcharArray");
		static_assert(std::is_same<jshortArray,decltype(array_type_from_element<jshort>())>::value, "array_type_from_element failed to convert jshort -> jshortArray");
		static_assert(std::is_same<jintArray,decltype(array_type_from_element<jint>())>::value, "array_type_from_element failed to convert jint -> jintArray");
		static_assert(std::is_same<jlongArray,decltype(array_type_from_element<jlong>())>::value, "array_type_from_element failed to convert jlong -> jlongArray");
		static_assert(std::is_same<jfloatArray,decltype(array_type_from_element<jfloat>())>::value, "array_type_from_element failed to convert jfloat -> jfloatArray");
		static_assert(std::is_same<jdoubleArray,decltype(array_type_from_element<jdouble>())>::value, "array_type_from_element failed to convert jdouble -> jdoubleArray");
		static_assert(std::is_same<jobjectArray,decltype(array_type_from_element<jobject>())>::value, "array_type_from_element failed to convert jobject -> jobjectArray");
	}

	template <typename ArrayType>
	constexpr auto element_type_from_array() {
		static_assert(is_array<ArrayType>::value, "ArrayType must be an array type.");

		if constexpr (std::is_same<ArrayType,jobjectArray>::value) {
			return jobject{nullptr};
		}

		if constexpr (std::is_same<ArrayType,jbooleanArray>::value) {
			return jboolean{0};
		}

		if constexpr (std::is_same<ArrayType,jbyteArray>::value) {
			return jbyte{0};
		}

		if constexpr (std::is_same<ArrayType,jcharArray>::value) {
			return jchar{0};
		}

		if constexpr (std::is_same<ArrayType,jshortArray>::value) {
			return jshort{0};
		}

		if constexpr (std::is_same<ArrayType,jintArray>::value) {
			return jint{0};
		}

		if constexpr (std::is_same<ArrayType,jlongArray>::value) {
			return jlong{0};
		}

		if constexpr (std::is_same<ArrayType,jfloatArray>::value) {
			return jfloat{0};
		}

		if constexpr (std::is_same<ArrayType,jdoubleArray>::value) {
			return jdouble{0};
		}
	}

	[[maybe_unused]] constexpr auto test_element_type_from_array() {
		static_assert(std::is_same<jboolean,decltype(element_type_from_array<jbooleanArray>())>::value, "element_type_from_array failed to convert jbooleanArray -> jboolean");
		static_assert(std::is_same<jbyte,decltype(element_type_from_array<jbyteArray>())>::value, "element_type_from_array failed to convert jbyteArray -> jbyte");
		static_assert(std::is_same<jchar,decltype(element_type_from_array<jcharArray>())>::value, "element_type_from_array failed to convert jcharArray -> jchar");
		static_assert(std::is_same<jshort,decltype(element_type_from_array<jshortArray>())>::value, "element_type_from_array failed to convert jshortArray -> jshort");
		static_assert(std::is_same<jint,decltype(element_type_from_array<jintArray>())>::value, "element_type_from_array failed to convert jintArray -> jint");
		static_assert(std::is_same<jlong,decltype(element_type_from_array<jlongArray>())>::value, "element_type_from_array failed to convert jlongArray -> jlong");
		static_assert(std::is_same<jfloat,decltype(element_type_from_array<jfloatArray>())>::value, "element_type_from_array failed to convert jfloatArray -> jfloat");
		static_assert(std::is_same<jdouble,decltype(element_type_from_array<jdoubleArray>())>::value, "element_type_from_array failed to convert jdoubleArray -> jdouble");
		static_assert(std::is_same<jobject,decltype(element_type_from_array<jobjectArray>())>::value, "element_type_from_array failed to convert jobjectArray -> jobject");
	}
}

#endif //MOLCH_JNI_TYPE_TRANSFORMATIONS_HPP
