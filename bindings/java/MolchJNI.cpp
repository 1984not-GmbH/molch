/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2018 1984not Security GmbH
 * Author: Bernd Herzmann, Max Bruckner
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

#include <cstring>
#include <limits>
#include <algorithm>

#include "de_hz1984not_crypto_Molch.h"
#include "1984notlib.hpp"

#ifdef __ANDROID__
#include <android/log.h>
#define android_only(code) code
#else
#define android_only(code)
#endif

#include "molch.h"
#include "molch/constants.h"
#include "molch/return-status.h"

template <size_t length>
auto array_from_jbyteArray(JNIEnv& environment, jbyteArray byte_array) noexcept -> std::optional<Molch::JNI::ByteArray<length>> {
	if (environment.GetArrayLength(byte_array) != length) {
		return std::nullopt;
	}

	const auto bytes = environment.GetByteArrayElements(byte_array, nullptr);
	if (bytes == nullptr) {
		return std::nullopt;
	}
	auto copied_array = Molch::JNI::ByteArray<length>();
	std::copy(bytes, bytes + length, std::begin(copied_array));
	environment.ReleaseByteArrayElements(byte_array, bytes, JNI_ABORT);

	return copied_array;
}

template <typename Container>
static auto jbyteArray_from(JNIEnv& environment, const Container& container) noexcept -> jbyteArray {
	if (std::size(container) > std::numeric_limits<jsize>::max()) {
		return nullptr;
	}

	auto java_array = environment.NewByteArray(static_cast<jsize>(std::size(container)));
	if (java_array == nullptr) {
		return nullptr;
	}
	auto data = environment.GetByteArrayElements(java_array, nullptr);
	std::copy(std::begin(container), std::end(container), data);

	environment.ReleaseByteArrayElements(java_array, data, 0);

	return java_array;
}

template <typename Pointer, typename = std::enable_if_t<std::is_pointer<Pointer>::value>>
struct AutoFreePointer {
	Pointer pointer = nullptr;

	~AutoFreePointer() noexcept {
		if (this->pointer != nullptr) {
			free(this->pointer);
		}
	}
};

class AutoReleaseJavaByteArray {
public:
	AutoReleaseJavaByteArray(JNIEnv& env, jbyteArray array) noexcept
			: env{env},
			array{array},
			bytes{reinterpret_cast<unsigned char*>(env.GetByteArrayElements(array, nullptr))},
			length{static_cast<size_t>(env.GetArrayLength(array))} {
		if (this->bytes == nullptr) {
			this->length = 0;
		}
	}

	auto size() const noexcept {
		return length;
	}

	auto data() noexcept -> unsigned char* {
		return bytes;
	}

	auto data() const noexcept -> const unsigned char* {
		return bytes;
	}

	~AutoReleaseJavaByteArray() noexcept {
		env.ReleaseByteArrayElements(array, reinterpret_cast<jbyte*>(bytes), 0);
	}

private:
	JNIEnv& env;
	jbyteArray array{nullptr};
	unsigned char* bytes{nullptr};
	size_t length{0};
};

static void print_info_error([[maybe_unused]] const char* calling_function, const return_status status) {
	size_t message_length = 0;
	const auto message = AutoFreePointer<char*>{molch_print_status(&message_length, status)};
	if (message.pointer == nullptr) {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, calling_function, "ERROR: Failed to print error."));
		return;
	}
	android_only(__android_log_print(ANDROID_LOG_DEBUG, calling_function, "%s\n", message.pointer);)
}

extern "C" {
	/* Support for throwing Java exceptions */
	typedef enum {
		SWIG_JavaOutOfMemoryError = 1,
		SWIG_JavaIOException,
		SWIG_JavaRuntimeException,
		SWIG_JavaIndexOutOfBoundsException,
		SWIG_JavaArithmeticException,
		SWIG_JavaIllegalArgumentException,
		SWIG_JavaNullPointerException,
		SWIG_JavaDirectorPureVirtual,
		SWIG_JavaUnknownError
	} SWIG_JavaExceptionCodes;

	typedef struct {
		SWIG_JavaExceptionCodes code;
		const char *java_exception;
	} SWIG_JavaExceptions_t;

	static char molchLastError[255];

	static void SWIG_JavaThrowException(JNIEnv *jenv, SWIG_JavaExceptionCodes code, const char *msg) {
		jclass excep;
		static const SWIG_JavaExceptions_t java_exceptions[] = {
			{ SWIG_JavaOutOfMemoryError, "java/lang/OutOfMemoryError" },
			{ SWIG_JavaIOException, "java/io/IOException" },
			{ SWIG_JavaRuntimeException, "java/lang/RuntimeException" },
			{ SWIG_JavaIndexOutOfBoundsException, "java/lang/IndexOutOfBoundsException" },
			{ SWIG_JavaArithmeticException, "java/lang/ArithmeticException" },
			{ SWIG_JavaIllegalArgumentException, "java/lang/IllegalArgumentException" },
			{ SWIG_JavaNullPointerException, "java/lang/NullPointerException" },
			{ SWIG_JavaDirectorPureVirtual, "java/lang/RuntimeException" },
			{ SWIG_JavaUnknownError,  "java/lang/UnknownError" },
			{ (SWIG_JavaExceptionCodes)0,  "java/lang/UnknownError" }
		};
		const SWIG_JavaExceptions_t *except_ptr = java_exceptions;

		while (except_ptr->code != code && except_ptr->code)
			except_ptr++;

		jenv->ExceptionClear();
		excep = jenv->FindClass(except_ptr->java_exception);
		if (excep)
			jenv->ThrowNew(excep, msg);
	}

	/* long[] support */
	static int SWIG_JavaArrayInLong (JNIEnv *jenv, jint **jarr, long **carr, jintArray input) {
		int i;
		jsize sz;
		if (!input) {
			SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null array");
			return 0;
		}
		sz = jenv->GetArrayLength(input);
		*jarr = jenv->GetIntArrayElements(input, nullptr);
		if (!*jarr)
			return 0;
		*carr = (long*) calloc((size_t)sz, sizeof(long));
		if (!*carr) {
			SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "array memory allocation failed");
			return 0;
		}
		for (i=0; i<sz; i++)
			(*carr)[i] = (long)(*jarr)[i];
		return 1;
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getMolchVersion(JNIEnv * env, [[maybe_unused]] jobject jObj) -> jstring {
		return env->NewStringUTF("Molch first Version 00.00.01");
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getMolchLastError(JNIEnv * env, [[maybe_unused]] jobject jObj) -> jstring {
		(void)jObj;
		return env->NewStringUTF(molchLastError);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getNunbercrypto_1box_1PUBLICKEYBYTES([[maybe_unused]] JNIEnv *env, [[maybe_unused]] jobject jObj) -> jint {
	    return static_cast<jint>(crypto_box_PUBLICKEYBYTES);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getNunberprekey_1list([[maybe_unused]] JNIEnv *env, [[maybe_unused]] jobject jObj) -> jint {
		// FIXME: This must never be used because the format of the prekey list is an implementation detail
		return static_cast<jint>((PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES) + 104);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getCONVERSATION_1ID_1SIZE([[maybe_unused]] JNIEnv *env, [[maybe_unused]] jobject jObj) -> jint {
		return static_cast<jint>(CONVERSATION_ID_SIZE);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getPREKEY_1AMOUNT([[maybe_unused]] JNIEnv *env, [[maybe_unused]] jobject jObj) -> jint {
		return static_cast<jint>(PREKEY_AMOUNT);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getBackupKeySize([[maybe_unused]] JNIEnv *env, [[maybe_unused]] jobject jObj) -> jint {
		return static_cast<jint>(BACKUP_KEY_SIZE);
	}

	static auto vector_from_jbyteArray(JNIEnv& environment, const jbyteArray byte_array) -> std::optional<Molch::JNI::ByteVector> {
		const auto size = static_cast<size_t>(environment.GetArrayLength(byte_array));
		const auto bytes = environment.GetByteArrayElements(byte_array, nullptr);
		if (bytes == nullptr) {
			return std::nullopt;
		}
		auto uchars = Molch::JNI::ByteVector(size, '\0');
		std::copy(bytes, bytes + size, std::data(uchars));
		environment.ReleaseByteArrayElements(byte_array, bytes, JNI_ABORT);

		return uchars;
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getUserName(
			JNIEnv *env,
			[[maybe_unused]] jobject jObj,
			[[maybe_unused]] jbyteArray jarg1,
			[[maybe_unused]] jint jlen1,
			[[maybe_unused]] jbyteArray jarg2,
			[[maybe_unused]] jint jlen2,
			[[maybe_unused]] jbyteArray jarg3,
			[[maybe_unused]] jint jlen3,
			[[maybe_unused]] jbyteArray jarg4,
			[[maybe_unused]] jint jlen4) -> jbyteArray {
		constexpr auto byte_array = Molch::JNI::ByteArray<5>{41,42,43,43,44};
		return jbyteArray_from(*env, byte_array);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getvCardInfoAvatar(
			JNIEnv *env,
			[[maybe_unused]] jobject jObj,
			jbyteArray public_key,
			[[maybe_unused]] jint public_key_length,
			jbyteArray prekey_list,
			[[maybe_unused]] jint prekey_list_length,
			jbyteArray avatar_data,
			[[maybe_unused]] jint jlen3) -> jbyteArray {
		const auto public_key_array_optional = array_from_jbyteArray<PUBLIC_MASTER_KEY_SIZE>(*env, public_key);
		const auto prekey_list_vector_optional = vector_from_jbyteArray(*env, prekey_list);
		const auto avatar_data_vector_optional = vector_from_jbyteArray(*env, avatar_data);

		if ((not public_key_array_optional.has_value())
				or (not prekey_list_vector_optional.has_value())
				or (not avatar_data_vector_optional.has_value())) {
			return nullptr;
		}
		const auto& public_key_array = public_key_array_optional.value();
		const auto& prekey_list_vector = prekey_list_vector_optional.value();
		const auto& avatar_data_vector = avatar_data_vector_optional.value();

		const auto optional_new_vcard = Molch::JNI::getvCardInfoAvatar(public_key_array, prekey_list_vector, avatar_data_vector);
		if (not optional_new_vcard.has_value()) {
			return nullptr;
		}
		const auto& new_vcard = optional_new_vcard.value();

		return jbyteArray_from(*env, new_vcard);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getvCardAvatar(
			JNIEnv *env,
			[[maybe_unused]] jobject jObj,
			[[maybe_unused]] jbyteArray jarg1,
			[[maybe_unused]] jint jlen1) -> jbyteArray {
		const auto bytes = Molch::JNI::ByteArray<5>{41, 42, 43, 43, 44};
		return jbyteArray_from(*env, bytes);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getvCardPubKey(
			JNIEnv *env,
			[[maybe_unused]] jobject jObj,
			jbyteArray jarg1,
			[[maybe_unused]] jint jlen1) -> jbyteArray {
		const auto avatar_data_vector_optional = vector_from_jbyteArray(*env, jarg1);
		if (not avatar_data_vector_optional.has_value()) {
			return nullptr;
		}
		const auto& avatar_data_vector = avatar_data_vector_optional.value();

		const auto public_key_optional = Molch::JNI::getvCardPubKey(avatar_data_vector);
		if (not public_key_optional.has_value()) {
			return nullptr;
		}
		const auto& public_key = public_key_optional.value();

		return jbyteArray_from(*env, public_key);
	}

	JNIEXPORT auto JNICALL Java_de_hz1984not_crypto_Molch_getvCardpreKeys(
			JNIEnv *env,
			[[maybe_unused]] jobject jObj,
			jbyteArray avatar_data,
			[[maybe_unused]] jint jlen1) -> jbyteArray {
		const auto avatar_data_vector_optional = vector_from_jbyteArray(*env, avatar_data);
		if (not avatar_data_vector_optional.has_value()) {
			return nullptr;
		}
		const auto& avatar_data_vector = avatar_data_vector_optional.value();

		const auto prekey_list_optional = Molch::JNI::getvCardPreKey(avatar_data_vector);
		if (not prekey_list_optional.has_value()) {
			return nullptr;
		}
		const auto& prekey_list = prekey_list_optional.value();

		return jbyteArray_from(*env, prekey_list);
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateUserFromNativeCode(
			JNIEnv * env,
			[[maybe_unused]] jobject jOgj,
			jbyteArray public_master_key_jarray,
			[[maybe_unused]] jint unused_public_master_key_length,
			jbyteArray prekey_list_jarray,
			[[maybe_unused]] jint unused_prekey_list_length,
			jbyteArray random_data_jarray,
			[[maybe_unused]] jint unused_random_data_length,
			[[maybe_unused]] jbyteArray unused_backup_key_jarray,
			[[maybe_unused]] jint unused_backup_key_length) {
		auto public_master_key = AutoReleaseJavaByteArray(*env, public_master_key_jarray);
		const auto random_data = AutoReleaseJavaByteArray(*env, random_data_jarray);

		unsigned char* prekey_list = nullptr;
		size_t prekey_list_length = 0;

		auto backup_key = std::array<unsigned char,BACKUP_KEY_SIZE>();

		auto status = molch_create_user(
				std::data(public_master_key),
				std::size(public_master_key),
				&prekey_list,
				&prekey_list_length,
				std::data(backup_key),
				std::size(backup_key),
				nullptr,
				nullptr,
				std::data(random_data),
				std::size(random_data));
		if (status.status != status_type::SUCCESS) {
			print_info_error(__FUNCTION__, status);
			molch_destroy_return_status(&status);
			return nullptr;
		}

		if (prekey_list == nullptr) {
			return nullptr;
		}

		auto prekey_list_jarray_data = reinterpret_cast<unsigned char*>(env->GetByteArrayElements(prekey_list_jarray, nullptr));
		if (prekey_list_jarray_data == nullptr) {
			return nullptr;
		}
		const auto prekey_list_jarray_length = static_cast<size_t>(env->GetArrayLength(prekey_list_jarray));
		if (prekey_list_length != prekey_list_jarray_length) {
			return nullptr;
		}

		std::copy(
				prekey_list,
				prekey_list + prekey_list_length,
				prekey_list_jarray_data);
		env->ReleaseByteArrayElements(prekey_list_jarray, reinterpret_cast<jbyte*>(prekey_list_jarray_data), 0);

		return nullptr;
	}

	JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchDestroyUserFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray public_identity_key, jint public_master_key_lengthin, jbyteArray jarg2) {
		jint jresult = 0;
		unsigned char *arg1 = nullptr;
		unsigned char *arg2 = nullptr;
		(void)env;
		(void)jOgj;
		arg1 = (unsigned char *) env->GetByteArrayElements(public_identity_key, nullptr);
		arg2 = (unsigned char *) env->GetByteArrayElements(jarg2, nullptr);
		size_t public_master_key_length;
		public_master_key_length = (size_t)public_master_key_lengthin;

		size_t json_export_length = 0;
		return_status retStatus;
		int retVal = 0;
		retStatus = molch_destroy_user(arg1, public_master_key_length, &arg2, &json_export_length);

		if (retStatus.status != status_type::SUCCESS) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			retVal = -1;
		}

		jresult = (jint) retVal;
		env->ReleaseByteArrayElements(public_identity_key, (jbyte *) arg1, 0);
		env->ReleaseByteArrayElements(jarg2, (jbyte *) arg2, 0);

		return jresult;
	}

	JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchUserCountFromNativeCode(JNIEnv *env, jobject jOgj) {
		jint jresult = 0;
		(void)env;
		(void)jOgj;

		size_t retVal = molch_user_count();
		jresult = (jint) retVal;

		return jresult;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchUserListFromNativeCode(JNIEnv *env, jobject jOgj, jintArray count) {
		(void)env;
		(void)jOgj;
		jint* jarr2 = nullptr;
		long* arg2 = nullptr;

		if (!SWIG_JavaArrayInLong(env, &jarr2, &arg2, count)) {
			return nullptr;
		}

		size_t tmpCount = 0;
		unsigned char* retptr;
		return_status retStatus;
		size_t user_list_length = 0;
		retStatus = molch_list_users(&retptr, &user_list_length, &tmpCount);
		if ((tmpCount > std::numeric_limits<jint>::max())
				or (tmpCount > std::numeric_limits<long>::max())) {
			return nullptr;
		}
		if (arg2) {
			*arg2 = (long) tmpCount;
		}

		size_t sizeByteUrl = tmpCount;

		if ((retStatus.status != status_type::SUCCESS)
				or (sizeByteUrl > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)sizeByteUrl);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < sizeByteUrl; index++) {
			bytes[index] = (jbyte)retptr[index];
		}
		free(retptr);

		env->SetByteArrayRegion(data, 0, (jsize)sizeByteUrl, bytes);

		return data;
	}

	JNIEXPORT void JNICALL Java_de_hz1984not_crypto_Molch_molchDestroyAllUsersFromNativeCode(JNIEnv *env, jobject jOgj) {
		(void)env;
		(void)jOgj;

		molch_destroy_all_users();
	}

	JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchGetMessageTypeFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2) {
		jint jresult = 0 ;
		unsigned char *arg1 = nullptr;
		(void)env;
		(void)jOgj;
		arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		size_t arg2 ;
		arg2 = (size_t)jarg2;
		molch_message_type tmpResult = molch_get_message_type(arg1, arg2);

		int result = (int) tmpResult;
		jresult = (jint)result;
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);

		return jresult;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin, jstring jarg2, jint jarg3, jbyteArray jarg4, jint prekey_list_lengthin, jbyteArray jarg5, jint sender_public_master_key_lengthin, jbyteArray jarg6, jint receiver_public_master_key_lengthin) {
		unsigned char *arg1 = nullptr;
		(void)env;
		(void)jOgj;
		arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		const unsigned char *arg2 = nullptr;
		if (jarg2) {
			arg2 = (const unsigned char *)env->GetStringUTFChars(jarg2, nullptr);
			if (!arg2) {
				return nullptr;
			}
		}
		size_t arg3 ;
		size_t conversation_id_length;
		size_t sender_public_master_key_length;
		size_t receiver_public_master_key_length;
		size_t prekey_list_length;
		arg3 = (size_t)jarg3;
		conversation_id_length = (size_t)conversation_id_lengthin;
		sender_public_master_key_length = (size_t)sender_public_master_key_lengthin;
		receiver_public_master_key_length = (size_t)receiver_public_master_key_lengthin;
		prekey_list_length = (size_t)prekey_list_lengthin;

		unsigned char *arg4 = (unsigned char *) env->GetByteArrayElements(jarg4, nullptr);
		unsigned char *arg5 = (unsigned char *) env->GetByteArrayElements(jarg5, nullptr);
		unsigned char *arg6 = (unsigned char *) env->GetByteArrayElements(jarg6, nullptr);

		unsigned char *alice_send_packet = nullptr;
		size_t packet_length = 0;
		unsigned char * json_export = nullptr;
		return_status retStatus;
		retStatus = molch_start_send_conversation(arg1, conversation_id_length, &alice_send_packet, &packet_length, arg5, sender_public_master_key_length, arg6, receiver_public_master_key_length, arg4, prekey_list_length, arg2, arg3, nullptr, nullptr);
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);
		if (arg2) env->ReleaseStringUTFChars(jarg2, (const char *)arg2);

		env->ReleaseByteArrayElements(jarg4, (jbyte *) arg4, 0);
		env->ReleaseByteArrayElements(jarg5, (jbyte *) arg5, 0);
		env->ReleaseByteArrayElements(jarg6, (jbyte *) arg6, 0);

		if ((retStatus.status != status_type::SUCCESS)
				or (packet_length > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)packet_length);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		// creat bytes from byteUrl
		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < packet_length; index++) {
			bytes[index] = (jbyte)alice_send_packet[index];
		}
		// move from the temp structure to the java structure
		env->SetByteArrayRegion(data, 0, (jsize)packet_length, bytes);
		free(alice_send_packet);

		if (json_export != nullptr) {
			free(json_export);
		}

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin, jbyteArray jarg2, jint jarg3, jbyteArray jarg4, jint jpre_keys_lengthin, jbyteArray jarg5, jint sender_public_master_key_lengthin, jbyteArray jarg6, jint receiver_public_master_key_lengthin) {
		(void)jpre_keys_lengthin;
		(void)env;
		(void)jOgj;
		unsigned char *arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		unsigned char *arg2 = (unsigned char *) env->GetByteArrayElements(jarg2, nullptr);
		auto arg3 = static_cast<size_t>(jarg3);
		auto conversation_id_length = static_cast<size_t>(conversation_id_lengthin);
		auto sender_public_master_key_length = static_cast<size_t>(sender_public_master_key_lengthin);
		auto receiver_public_master_key_length = static_cast<size_t>(receiver_public_master_key_lengthin);
		jsize jpre_keys_length = 0;
		unsigned char *arg4 = nullptr;
		arg4 = (unsigned char *) env->GetByteArrayElements(jarg4, nullptr);
		jpre_keys_length = env->GetArrayLength(jarg4);
		unsigned char *arg5 = nullptr;
		arg5 = (unsigned char *) env->GetByteArrayElements(jarg5, nullptr);
		unsigned char *arg6 = nullptr;
		arg6 = (unsigned char *) env->GetByteArrayElements(jarg6, nullptr);

		unsigned char *alice_receive_packet;
		size_t alice_message_length = 0;
		size_t pre_keys_length = (size_t) jpre_keys_length;
		unsigned char *my_public_prekeys = nullptr;  //arg4
		unsigned char * json_export = nullptr;
		size_t json_export_length = 0;
		return_status retStatus;
		retStatus = molch_start_receive_conversation(arg1, conversation_id_length, &my_public_prekeys, &pre_keys_length, &alice_receive_packet, &alice_message_length, arg6, receiver_public_master_key_length, arg5, sender_public_master_key_length, arg2, arg3, &json_export, &json_export_length);
		if ((alice_message_length > std::numeric_limits<jsize>::max())
				or (pre_keys_length > std::numeric_limits<jsize>::max())) {
			return nullptr;
		}
		int preKeyerrorCode = 0;
		if (retStatus.status == status_type::SUCCESS) {
			if (my_public_prekeys == nullptr) {
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: notNewPreKeyList;", "error: %d\n", retStatus.status);)
				preKeyerrorCode = -10;
				//return nullptr;
			}
			else {
				if (jpre_keys_length == (jsize)pre_keys_length) {
					for (size_t index = 0; index < pre_keys_length; index++) {
						arg4[index] = my_public_prekeys[index];
					}
					free(my_public_prekeys);
				}
				else {
					android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: preKeyListdifferent;", "error: %d\n", retStatus.status);)
					preKeyerrorCode = -11;
				}
			}
		}
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);
		env->ReleaseByteArrayElements(jarg2, (jbyte *) arg2, 0);
		env->ReleaseByteArrayElements(jarg5, (jbyte *) arg5, 0);
		env->ReleaseByteArrayElements(jarg6, (jbyte *) arg6, 0);

		if ((retStatus.status != status_type::SUCCESS) or (preKeyerrorCode != 0)) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)alice_message_length);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < alice_message_length; index++) {
			bytes[index] = (jbyte)alice_receive_packet[index];
		}
		env->SetByteArrayRegion(data, 0, (jsize)alice_message_length, bytes);
		free(alice_receive_packet);

		if (json_export != nullptr)
		{
			free(json_export);
		}

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode(JNIEnv *env, jobject jOgj, jstring jarg1, jint jarg2, jbyteArray jarg3, jint conversation_id_lengthin) {
		(void)env;
		(void)jOgj;
		const unsigned char *arg1 = nullptr;
		if (jarg1) {
			arg1 = (const unsigned char*)env->GetStringUTFChars(jarg1, nullptr);
			if (!arg1) {
				return nullptr;
			}
		}
		size_t arg2 ;
		size_t conversation_id_length;
		arg2 = (size_t)jarg2;
		conversation_id_length = (size_t)conversation_id_lengthin;
		unsigned char *arg3 = nullptr;
		arg3 = (unsigned char *) env->GetByteArrayElements(jarg3, nullptr);

		unsigned char *packet;
		size_t packet_length = 0;
		unsigned char * conversation_json_export = nullptr;
		size_t json_export_conversation_length = 0;
		return_status retStatus;
		retStatus = molch_encrypt_message(&packet, &packet_length, arg3, conversation_id_length, (const unsigned char*)arg1, arg2, &conversation_json_export, &json_export_conversation_length);
		if (arg1) {
			env->ReleaseStringUTFChars(jarg1, (const char *)arg1);
		}
		env->ReleaseByteArrayElements(jarg3, (jbyte *) arg3, 0);

		if ((retStatus.status != status_type::SUCCESS)
				or (packet_length > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)packet_length);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		// creat bytes from byteUrl
		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < packet_length; index++) {
			bytes[index] = (jbyte)packet[index];
		}
		// move from the temp structure to the java structure
		env->SetByteArrayRegion(data, 0, (jsize)packet_length, bytes);
		free(packet);

		if (conversation_json_export != nullptr)
		{
			free(conversation_json_export);
		}

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchDecryptMessageFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2, jbyteArray jarg3, jint conversation_id_lengthin) {
		(void)env;
		(void)jOgj;
		unsigned char *arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		auto arg2 = (size_t)jarg2;
		auto conversation_id_length = (size_t)conversation_id_lengthin;
		unsigned char *arg3 = (unsigned char *) env->GetByteArrayElements(jarg3, nullptr);

		unsigned char *packet;
		size_t packet_length = 0;
		uint32_t receive_message_number = 0;
		uint32_t previous_receive_message_number = 0;
		unsigned char * conversation_json_export = nullptr;
		size_t conversation_json_export_length = 0;
		return_status retStatus;
		retStatus = molch_decrypt_message(&packet, &packet_length, &receive_message_number, &previous_receive_message_number, arg3, conversation_id_length, arg1, arg2, &conversation_json_export, &conversation_json_export_length);
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);
		env->ReleaseByteArrayElements(jarg3, (jbyte *) arg3, 0);

		if ((retStatus.status != status_type::SUCCESS)
				or (packet_length > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)packet_length);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}
		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < packet_length; index++) {
			bytes[index] = (jbyte)packet[index];
		}
		env->SetByteArrayRegion(data, 0, (jsize)packet_length, bytes);
		free(packet);

		if (conversation_json_export != nullptr)
		{
			free(conversation_json_export);
		}

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchEndConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin) {
		unsigned char *arg1 = nullptr;
		(void)env;
		(void)jOgj;
		arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		size_t conversation_id_length;
		conversation_id_length = (size_t)conversation_id_lengthin;

		size_t json_export_length = 0;
		unsigned char * json_export = nullptr;
		molch_end_conversation(arg1, conversation_id_length, &json_export, &json_export_length);
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);

		jbyteArray data = nullptr;
		if ((json_export_length != 0) && (json_export_length < std::numeric_limits<jsize>::max())) {
			data = env->NewByteArray((jsize)json_export_length);
			if (data == nullptr) {
				return nullptr; //  out of memory error thrown
			}

			// creat bytes from byteUrl
			jbyte *bytes = env->GetByteArrayElements(data, nullptr);
			for (size_t index = 0; index < json_export_length; index++) {
				bytes[index] = (jbyte)json_export[index];
			}

			// move from the temp structure to the java structure
			env->SetByteArrayRegion(data, 0, (jsize)json_export_length, bytes);
		}

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2) {
		unsigned char *arg1 = nullptr;
		(void)env;
		(void)jOgj;
		arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);

		size_t conversation_list_length = 0;
		size_t number_of_conversations = 0;
		unsigned char *conversation_list = nullptr;

		android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode: ", "arg2: %d\n", (int) jarg2);)

		return_status retStatus;
		if (jarg2 < 0) {
			print_info_error(__FUNCTION__, retStatus);
			return nullptr;
		}
		size_t arg2 = (size_t)jarg2;
		retStatus = molch_list_conversations(&conversation_list, &conversation_list_length, &number_of_conversations, arg1, arg2);
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);

		android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode: ", "retStatus.status: %d; number_of_conversations: %d\n", (int) retStatus.status, (int) number_of_conversations);)

		if ((conversation_list == nullptr)
				or (number_of_conversations == 0)
				or (retStatus.status != status_type::SUCCESS)
				or (arg2 > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)arg2);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		// creat bytes from byteUrl
		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < arg2; index++) {
			bytes[index] = (jbyte)conversation_list[(number_of_conversations - 1) + index];
		}

		// move from the temp structure to the java structure
		env->SetByteArrayRegion(data, 0, (jsize)arg2, bytes);

		return data;
	}

	JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchJsonExportFromNativeCode(JNIEnv *env, jobject jOgj) {
		(void)jOgj;

		size_t imported_json_length;
		return_status retStatus;
		unsigned char *imported_json;
		retStatus = molch_export(&imported_json, &imported_json_length);
		if ((imported_json == nullptr)
				or (retStatus.status != status_type::SUCCESS)
				or (imported_json_length > std::numeric_limits<jsize>::max())) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
			return nullptr;
		}

		jbyteArray data = env->NewByteArray((jsize)imported_json_length);
		if (data == nullptr) {
			return nullptr; //  out of memory error thrown
		}

		// creat bytes from byteUrl
		jbyte *bytes = env->GetByteArrayElements(data, nullptr);
		for (size_t index = 0; index < imported_json_length; index++) {
			bytes[index] = (jbyte)imported_json[index];
		}

		// move from the temp structure to the java structure
		env->SetByteArrayRegion(data, 0, (jsize)imported_json_length, bytes);

		return data;
	}

	JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2, jbyteArray jnewbackupkeyin, jint jnewbackupkeyin_length, jbyteArray joldbackupkeyin, jint joldbackupkeyin_length) {
		jint jresult = 0 ;
		(void)env;
		(void)jOgj;
		unsigned char *arg1 = (unsigned char *) env->GetByteArrayElements(jarg1, nullptr);
		unsigned char *newbackupkey = (unsigned char *) env->GetByteArrayElements(jnewbackupkeyin, nullptr);
		unsigned char *oldbackupkey = (unsigned char *) env->GetByteArrayElements(joldbackupkeyin, nullptr);

		size_t arg2;
		arg2 = (size_t)jarg2;
		size_t newbackupkeyin_length;
		newbackupkeyin_length = (size_t)jnewbackupkeyin_length;
		size_t oldbackupkeyin_length;
		oldbackupkeyin_length = (size_t)joldbackupkeyin_length;

		for (size_t index = 0; index < newbackupkeyin_length; ++index) {
			android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) newbackupkey[index]);)
		}
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode: ", "arg2: %d; %d; %d\n", (int) arg2, (int) newbackupkeyin_length, (int) oldbackupkeyin_length);)
		for (size_t index = 0; index < oldbackupkeyin_length; ++index) {
			android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) oldbackupkey[index]);)
		}

		return_status retStatus;
		//retStatus = molch_json_import(arg1, arg2);
		retStatus = molch_import(newbackupkey, newbackupkeyin_length, arg1, arg2, oldbackupkey, oldbackupkeyin_length);
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode: ", "retStatus.status: %d;\n", (int) retStatus.status);)
		jresult = (jint) retStatus.status;
		env->ReleaseByteArrayElements(jarg1, (jbyte *) arg1, 0);
		env->ReleaseByteArrayElements(jnewbackupkeyin, (jbyte *) newbackupkey, 0);
		env->ReleaseByteArrayElements(joldbackupkeyin, (jbyte *) oldbackupkey, 0);

		for (size_t index = 0; index < newbackupkeyin_length; ++index) {
			android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) newbackupkey[index]);)
		}

		if (retStatus.status != status_type::SUCCESS) {
			print_info_error(__FUNCTION__, retStatus);
			molch_destroy_return_status(&retStatus);
		}

		return jresult;
	}
}
