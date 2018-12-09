//
// Created by max on 04.12.18.
//

#ifndef MOLCH_JNI_FIELDS_HPP
#define MOLCH_JNI_FIELDS_HPP

#include "jni_type_traits.hpp"

namespace Molch::JNI {
	template <typename Type>
	constexpr auto set_field(JNIEnv& environment, jobject object, jfieldID field, Type value) {
		static_assert(is_java_type<Type>::value, "Type must be a Java Type.");

		if constexpr (is_object<Type>::value) {
			return environment.SetObjectField(object, field, value);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.SetBooleanField(object, field, value);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.SetByteField(object, field, value);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.SetCharField(object, field, value);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.SetShortField(object, field, value);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.SetIntField(object, field, value);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.SetLongField(object, field, value);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.SetFloatField(object, field, value);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.SetDoubleField(object, field, value);
		}
	}

	template <typename Type>
	constexpr auto set_static_field(JNIEnv& environment, jclass class_object, jfieldID field, Type value) {
		static_assert(is_java_type<Type>::value, "Type must be a Java Type.");

		if constexpr (is_object<Type>::value) {
			return environment.SetStaticObjectField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.SetStaticBooleanField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.SetStaticByteField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.SetStaticCharField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.SetStaticShortField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.SetStaticIntField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.SetStaticLongField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.SetStaticFloatField(class_object, field, value);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.SetStaticDoubleField(class_object, field, value);
		}
	}

	template <typename Type>
	constexpr auto get_field(JNIEnv& environment, jobject object, jfieldID field) {
		static_assert(is_java_type<Type>::value, "Type must be a Java Type.");

		if constexpr (std::is_same<Type,jobject>::value) {
			return environment.GetObjectField(object, field);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.GetBooleanField(object, field);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.GetByteField(object, field);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.GetCharField(object, field);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.GetShortField(object, field);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.GetIntField(object, field);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.GetLongField(object, field);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.GetFloatField(object, field);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.GetDoubleField(object, field);
		}
	}

	template <typename Type>
	constexpr auto get_static_field(JNIEnv& environment, jclass class_object, jfieldID field) {
		static_assert(is_java_type<Type>::value, "Type must be a Java Type.");

		if constexpr (std::is_same<Type,jobject>::value) {
			return environment.GetStaticObjectField(class_object, field);
		}

		if constexpr (std::is_same<Type,jboolean>::value) {
			return environment.GetStaticBooleanField(class_object, field);
		}

		if constexpr (std::is_same<Type,jbyte>::value) {
			return environment.GetStaticByteField(class_object, field);
		}

		if constexpr (std::is_same<Type,jchar>::value) {
			return environment.GetStaticCharField(class_object, field);
		}

		if constexpr (std::is_same<Type,jshort>::value) {
			return environment.GetStaticShortField(class_object, field);
		}

		if constexpr (std::is_same<Type,jint>::value) {
			return environment.GetStaticIntField(class_object, field);
		}

		if constexpr (std::is_same<Type,jlong>::value) {
			return environment.GetStaticLongField(class_object, field);
		}

		if constexpr (std::is_same<Type,jfloat>::value) {
			return environment.GetStaticFloatField(class_object, field);
		}

		if constexpr (std::is_same<Type,jdouble>::value) {
			return environment.GetStaticDoubleField(class_object, field);
		}
	}
}


#endif //MOLCH_JNI_FIELDS_HPP
