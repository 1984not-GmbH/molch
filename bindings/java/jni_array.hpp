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

#ifndef MOLCH_JNI_ARRAY_HPP
#define MOLCH_JNI_ARRAY_HPP

#include <optional>
#include <limits>

#include "jni_type_transformations.hpp"

namespace Molch::JNI {
	template <typename ArrayType>
	constexpr auto get_elements(JNIEnv& environment, const ArrayType array) -> std::optional<decltype(element_type_from_array<ArrayType>())*> {
		using ElementType = decltype(element_type_from_array<ArrayType>());
		static_assert(is_value_primitive<ElementType>::value, "ElementType needs to be a primitive value type.");

		if (array == nullptr) {
			return std::nullopt;
		}

		if constexpr (std::is_same<ArrayType,jbooleanArray>::value) {
			const auto elements{environment.GetBooleanArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jbyteArray>::value) {
			const auto elements = environment.GetByteArrayElements(array, nullptr);
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jcharArray>::value) {
			const auto elements{environment.GetCharArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jshortArray>::value) {
			const auto elements{environment.GetShortArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jintArray>::value) {
			const auto elements{environment.GetIntArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jlongArray>::value) {
			const auto elements{environment.GetLongArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jfloatArray>::value) {
			const auto elements{environment.GetFloatArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}

		if constexpr (std::is_same<ArrayType,jdoubleArray>::value) {
			const auto elements{environment.GetDoubleArrayElements(array, nullptr)};
			if (elements == nullptr) {
				return std::nullopt;
			}
			return elements;
		}
	}

	template <typename ElementType>
	constexpr auto new_array(JNIEnv& environment, jsize length) -> std::optional<decltype(array_type_from_element<ElementType>())> {
		using ArrayType = decltype(array_type_from_element<ElementType>());
		static_assert(is_value_primitive<ElementType>::value, "ElementType needs to be a primitive value type.");

		if ((length > std::numeric_limits<jsize>::max()) or (length < std::numeric_limits<jsize>::min())) {
			return std::nullopt;
		}

		if constexpr (std::is_same<ArrayType,jbooleanArray>::value) {
			const auto array{environment.NewBooleanArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jbyteArray>::value) {
			const auto array{environment.NewByteArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jcharArray>::value) {
			const auto array{environment.NewCharArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jshortArray>::value) {
			const auto array{environment.NewShortArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jintArray>::value) {
			const auto array{environment.NewIntArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jlongArray>::value) {
			const auto array{environment.NewLongArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jfloatArray>::value) {
			const auto array{environment.NewFloatArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}

		if constexpr (std::is_same<ArrayType,jdoubleArray>::value) {
			const auto array{environment.NewDoubleArray(length)};
			if (array == nullptr) {
				return std::nullopt;
			}
			return array;
		}
	}

	enum class ReleaseMode : jint {
		COPY_BACK = 0,
		COMMIT = JNI_COMMIT,
		ABORT = JNI_ABORT,
	};


	template <typename ArrayType>
	constexpr auto release(
			JNIEnv& environment,
			ArrayType array,
			decltype(element_type_from_array<ArrayType>())* elements, ReleaseMode mode = ReleaseMode::COPY_BACK) {
		static_assert(is_primitive_array<ArrayType>::value, "ArrayType must be an array of primitives");

		if ((array == nullptr) || (elements == nullptr)) {
			return;
		}

		const auto jint_mode{static_cast<jint>(mode)};

		if constexpr (std::is_same<ArrayType,jbooleanArray>::value) {
			environment.ReleaseBooleanArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jbyteArray>::value) {
			environment.ReleaseByteArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jcharArray>::value) {
			environment.ReleaseCharArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jshortArray>::value) {
			environment.ReleaseShortArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jintArray>::value) {
			environment.ReleaseIntArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jlongArray>::value) {
			environment.ReleaseLongArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jfloatArray>::value) {
			environment.ReleaseFloatArrayElements(array, elements, jint_mode);
			return;
		}

		if constexpr (std::is_same<ArrayType,jdoubleArray>::value) {
			environment.ReleaseDoubleArrayElements(array, elements, jint_mode);
			return;
		}
	}

	template <typename ElementType>
	class Array {
	private:
		using ArrayType = decltype(array_type_from_element<ElementType>());

		JNIEnv& environment;
		ArrayType _array{nullptr};
		ElementType* elements{nullptr};

		static constexpr auto assert_type() -> void {
			static_assert(is_value_primitive<ElementType>::value, "ElementType must be a value primitive");
		}

		Array(JNIEnv& environment, ArrayType array, ElementType* elements) noexcept
				: environment{environment},
				_array{array},
				elements{elements} {}
	public:

		static auto Create(JNIEnv& environment, ArrayType array) noexcept -> std::optional<Array> {
			if (array == nullptr) {
				return std::nullopt;
			}
			const auto elements_optional{get_elements(environment, array)};
			if (not elements_optional.has_value()) {
				return std::nullopt;
			}
			const auto elements{elements_optional.value()};

			return Array(environment, array, elements);
		}

		static auto Create(JNIEnv& environment, size_t length) noexcept -> std::optional<Array> {
			const auto array_optional{new_array<ElementType>(environment, static_cast<jsize>(length))};
			if (not array_optional.has_value()) {
				return std::nullopt;
			}
			const auto array{array_optional.value()};

			const auto elements_optional{get_elements(environment, array)};
			if (not elements_optional.has_value()) {
				return std::nullopt;
			}
			const auto elements{elements_optional.value()};

			return Array(environment, array, elements);
		}

		Array(const Array&) = delete;

		Array(Array&& other) noexcept
				: environment{other.environment},
				_array{other._array},
				elements{other.elements} {
			other._array = nullptr;
			other.elements = nullptr;
		}

		auto data() noexcept -> ElementType* {
			return this->elements;
		}

		auto data() const noexcept -> const ElementType* {
			return this->elements;
		}

		auto size() const noexcept -> size_t {
			return static_cast<size_t>(environment.GetArrayLength(_array));
		}

		auto array() noexcept {
			return this->_array;
		}

		~Array() {
			if ((_array == nullptr) or (elements == nullptr)) {
				return;
			}
			release(environment, _array, elements);
		}
	};
}

#endif //MOLCH_JNI_ARRAY_HPP
