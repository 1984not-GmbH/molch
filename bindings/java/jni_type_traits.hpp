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

#ifndef MOLCH_JNI_TYPE_TRAITS_HPP
#define MOLCH_JNI_TYPE_TRAITS_HPP

#include <jni.h>
#include <type_traits>

namespace Molch::JNI {
	template <typename Type>
	struct is_value_primitive {
		static constexpr auto value{std::is_same<Type, jboolean>::value
			or std::is_same<Type, jbyte>::value
			or std::is_same<Type, jchar>::value
			or std::is_same<Type, jshort>::value
			or std::is_same<Type, jint>::value
			or std::is_same<Type, jlong>::value
			or std::is_same<Type, jfloat>::value
			or std::is_same<Type, jdouble>::value};
	};

	[[maybe_unused]] constexpr auto test_is_value_primitive() -> void {
		static_assert(is_value_primitive<jboolean>::value, "jboolean not detected as value primitive");
		static_assert(is_value_primitive<jbyte>::value, "jbyte not detected as value primitive");
		static_assert(is_value_primitive<jchar>::value, "jchar not detected as value primitive");
		static_assert(is_value_primitive<jshort>::value, "jshort not detected as value primitive");
		static_assert(is_value_primitive<jint>::value, "jint not detected as value primitive");
		static_assert(is_value_primitive<jlong>::value, "jlong not detected as value primitive");
		static_assert(is_value_primitive<jfloat>::value, "jfloat not detected as value primitive");
		static_assert(is_value_primitive<jdouble>::value, "jdouble not detected as value primitive");
		static_assert(not is_value_primitive<void>::value, "void should not be a value primitive");
		static_assert(not is_value_primitive<jobject>::value, "jobject should not be a value primitive");
		static_assert(not is_value_primitive<jarray>::value, "jarray should not be a value primitive");
	}

	template <typename Type>
	struct is_primitive {
		static constexpr auto value{std::is_void<Type>::value or is_value_primitive<Type>::value};
	};

	[[maybe_unused]] constexpr auto test_is_primitive() -> void {
		static_assert(is_primitive<jboolean>::value, "jboolean not detected as primitive");
		static_assert(is_primitive<jbyte>::value, "jbyte not detected as primitive");
		static_assert(is_primitive<jchar>::value, "jchar not detected as primitive");
		static_assert(is_primitive<jshort>::value, "jshort not detected as primitive");
		static_assert(is_primitive<jint>::value, "jint not detected as primitive");
		static_assert(is_primitive<jlong>::value, "jlong not detected as primitive");
		static_assert(is_primitive<jfloat>::value, "jfloat not detected as primitive");
		static_assert(is_primitive<jdouble>::value, "jdouble not detected as primitive");
		static_assert(is_primitive<void>::value, "void not detected as primitive");
		static_assert(not is_value_primitive<jobject>::value, "jobject should not be a primitive");
		static_assert(not is_value_primitive<jarray>::value, "jarray should not be a primitive");
	}

	template<typename Type>
	struct is_primitive_array {
		static constexpr auto value{std::is_same<Type, jbooleanArray>::value
			or std::is_same<Type, jbyteArray>::value
			or std::is_same<Type, jcharArray>::value
			or std::is_same<Type, jshortArray>::value
			or std::is_same<Type, jintArray>::value
			or std::is_same<Type, jlongArray>::value
			or std::is_same<Type, jfloatArray>::value
			or std::is_same<Type, jdoubleArray>::value};
	};

	template<typename Type>
	using is_jarray = std::is_same<jarray,Type>;

	[[maybe_unused]] constexpr auto test_is_jarray() -> void {
		static_assert(is_jarray<jarray>::value, "jarray is not a jarray");
	}

	template <typename Type>
	struct is_array {
		static constexpr auto value{is_primitive_array<Type>::value
			or std::is_same<Type,jobjectArray>::value
			or is_jarray<Type>::value};
	};

	[[maybe_unused]] constexpr auto test_is_array() -> void {
		static_assert(is_array<jarray>::value, "jarray is not an array");
		static_assert(is_array<jbooleanArray>::value, "jbooleanArray is not an array");
		static_assert(is_array<jbyteArray>::value, "jbyteArray is not an array");
		static_assert(is_array<jcharArray>::value, "jcharArray is not an array");
		static_assert(is_array<jshortArray>::value, "jshortArray is not an array");
		static_assert(is_array<jintArray>::value, "jintArray is not an array");
		static_assert(is_array<jlongArray>::value, "jlongArray is not an array");
		static_assert(is_array<jfloatArray>::value, "jfloatArray is not an array");
		static_assert(is_array<jdoubleArray>::value, "jdoubleArray is not an array");
		static_assert(is_array<jobjectArray>::value, "jobjectArray is not an array");
		static_assert(not is_array<jobject>::value, "jobject should not be an array");
	}


	template <typename Type>
	using is_jobject = std::is_same<Type,jobject>;

	[[maybe_unused]] constexpr auto test_is_jobject() -> void {
		static_assert(is_jobject<jobject>::value, "jobject is not jobject");
	}

	template <typename Type>
	struct is_object {
		static constexpr auto value{std::is_same<jobject, Type>::value
			or std::is_same<jclass, Type>::value
			or std::is_same<jthrowable, Type>::value
			or std::is_same<jstring, Type>::value
			or is_array<Type>::value};
	};

	[[maybe_unused]] constexpr auto test_remove_pointer() -> void {
		static_assert(std::is_same<_jobject,std::remove_pointer<jobject>::type>::value, "Remove pointer works");
	}

	[[maybe_unused]] constexpr auto test_is_object() -> void {
		static_assert(is_object<jobject>::value, "jobject is not an object");
		static_assert(is_object<jclass>::value, "jclass is not an object");
		static_assert(is_object<jthrowable>::value, "jthrowable is not an object");
		static_assert(is_object<jstring>::value, "jstring is not an object");
		static_assert(is_object<jarray>::value, "jarray is not an object");
		static_assert(is_object<jbooleanArray>::value, "jbooleanArray is not an object");
		static_assert(is_object<jbyteArray>::value, "jbyteArray is not an object");
		static_assert(is_object<jcharArray>::value, "jcharArray is not an object");
		static_assert(is_object<jshortArray>::value, "jshortArray is not an object");
		static_assert(is_object<jintArray>::value, "jintArray is not an object");
		static_assert(is_object<jlongArray>::value, "jlongArray is not an object");
		static_assert(is_object<jfloatArray>::value, "jfloatArray is not an object");
		static_assert(is_object<jdoubleArray>::value, "jdoubleArray is not an object");
		static_assert(is_object<jobjectArray>::value, "jobjectxArray is not an object");
		static_assert(not is_object<jbyte>::value, "jbyte should not be an object");
	}

	template<typename Type>
	struct is_java_type {
		static constexpr auto value{is_object<Type>::value or is_primitive<Type>::value};
	};

	[[maybe_unused]] constexpr auto test_is_java_type() -> void {
		static_assert(is_java_type<jobject>::value, "jobject is not a java type");
		static_assert(is_java_type<jclass>::value, "jclass is not a java type");
		static_assert(is_java_type<jthrowable>::value, "jthrowable is not a java type");
		static_assert(is_java_type<jstring>::value, "jstring is not a java type");
		static_assert(is_java_type<jarray>::value, "jarray is not a java type");
		static_assert(is_java_type<jbooleanArray>::value, "jbooleanArray is not a java type");
		static_assert(is_java_type<jbyteArray>::value, "jbyteArray is not a java type");
		static_assert(is_java_type<jcharArray>::value, "jcharArray is not a java type");
		static_assert(is_java_type<jshortArray>::value, "jshortArray is not a java type");
		static_assert(is_java_type<jintArray>::value, "jintArray is not a java type");
		static_assert(is_java_type<jlongArray>::value, "jlongArray is not a java type");
		static_assert(is_java_type<jfloatArray>::value, "jfloatArray is not a java type");
		static_assert(is_java_type<jdoubleArray>::value, "jdoubleArray is not a java type");
		static_assert(is_java_type<jobjectArray>::value, "jobjectxArray is not a java type");
		static_assert(is_java_type<jboolean>::value, "jboolean is not a java type");
		static_assert(is_java_type<jbyte>::value, "jbyte is not a java type");
		static_assert(is_java_type<jchar>::value, "jchar is not a java type");
		static_assert(is_java_type<jshort>::value, "jshort is not a java type");
		static_assert(is_java_type<jint>::value, "jint is not a java type");
		static_assert(is_java_type<jlong>::value, "jlong is not a java type");
		static_assert(is_java_type<jfloat>::value, "jfloat is not a java type");
		static_assert(is_java_type<jdouble>::value, "jdouble is not a java type");
		static_assert(is_java_type<void>::value, "void is not a java type");
	}
}

#endif //MOLCH_JNI_TYPE_TRAITS_HPP
