/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Bernd Herzmann
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

#include <string.h>

#include <sodium.h>
#include "de_hz1984not_crypto_Molch.h"
#include "1984notlib.h"

#ifdef __ANDROID__
#include <android/log.h>
#define android_only(code) code
#else
#define android_only(code)
#endif

#include "molch.h"
#include "molch/constants.h"
#include "molch/return-status.h"

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

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

static void SWIGUNUSED SWIG_JavaThrowException(JNIEnv *jenv, SWIG_JavaExceptionCodes code, const char *msg) {
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

	(*jenv)->ExceptionClear(jenv);
	excep = (*jenv)->FindClass(jenv, except_ptr->java_exception);
	if (excep)
		(*jenv)->ThrowNew(jenv, excep, msg);
}

/* long[] support */
static int SWIG_JavaArrayInLong (JNIEnv *jenv, jint **jarr, long **carr, jintArray input) {
	int i;
	jsize sz;
	if (!input) {
		SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null array");
		return 0;
	}
	sz = (*jenv)->GetArrayLength(jenv, input);
	*jarr = (*jenv)->GetIntArrayElements(jenv, input, 0);
	if (!*jarr)
		return 0;
	*carr = (long*) calloc(sz, sizeof(long));
	if (!*carr) {
		SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "array memory allocation failed");
		return 0;
	}
	for (i=0; i<sz; i++)
		(*carr)[i] = (long)(*jarr)[i];
	return 1;
}

static void print_info_error(char *callFunct, return_status retStatus) {
	error_message *infoerror;
	char tmpStr[255];
	int tmpLength = 0;
	strcpy(molchLastError, "");
	if (retStatus.error != NULL) {
		infoerror = retStatus.error;
		sprintf(tmpStr, "%s;", callFunct);
		tmpLength += strlen(tmpStr);
		strcat(molchLastError, tmpStr);
		while (infoerror != NULL) {
			sprintf(tmpStr, "error;%d;%s;", infoerror->status, infoerror->message);
			if (tmpLength < 255 - strlen(tmpStr)) {
				strcat(molchLastError, tmpStr);
			}
			android_only(__android_log_print(ANDROID_LOG_DEBUG, callFunct, "error;%d;%s\n", infoerror->status, infoerror->message);)
			infoerror = infoerror->next;
		};
	}
}

JNIEXPORT jstring JNICALL Java_de_hz1984not_crypto_Molch_getMolchVersion(JNIEnv * env, jobject jObj) {
	return (*env)->NewStringUTF(env, "Molch first Version 00.00.01");
}

JNIEXPORT jstring JNICALL Java_de_hz1984not_crypto_Molch_getMolchLastError(JNIEnv * env, jobject jObj) {
	return (*env)->NewStringUTF(env, molchLastError);
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_getNunbercrypto_1box_1PUBLICKEYBYTES(JNIEnv *env, jobject jObj) {
	jint jresult = 0;

	jresult = (jint) (crypto_box_PUBLICKEYBYTES);

	return jresult;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_getNunberprekey_1list(JNIEnv *env, jobject jObj) {
	jint jresult = 0;

	jresult = (jint) ((PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES) + 104);  //BHR:TODO

	return jresult;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_getCONVERSATION_1ID_1SIZE(JNIEnv *env, jobject jObj) {
	jint jresult = 0;

	jresult = (jint) (CONVERSATION_ID_SIZE);

	return jresult;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_getPREKEY_1AMOUNT(JNIEnv *env, jobject jObj) {
	jint jresult = 0;

	jresult = (jint) (PREKEY_AMOUNT);

	return jresult;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_getBackupKeySize(JNIEnv *env, jobject jObj) {
	jint jresult = 0;

	jresult = (jint) (BACKUP_KEY_SIZE);

	return jresult;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_getUserName(JNIEnv *env, jobject jObj, jbyteArray jarg1, jint jlen1, jbyteArray jarg2, jint jlen2, jbyteArray jarg3, jint jlen3, jbyteArray jarg4, jint jlen4) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	unsigned char *arg2 = (unsigned char *) 0 ;
	unsigned char *arg3 = (unsigned char *) 0 ;
	unsigned char *arg4 = (unsigned char *) 0 ;
	(void)env;
	(void)jObj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	{
		arg2 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg2, 0);
	}
	{
		arg3 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg3, 0);
	}
	{
		arg4 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg4, 0);
	}

	unsigned long long len1;
	len1 = (unsigned long long)jlen1;
	unsigned long long len2;
	len2 = (unsigned long long)jlen2;
	unsigned long long len3;
	len3 = (unsigned long long)jlen3;
	unsigned long long len4;
	len4 = (unsigned long long)jlen4;

	//int ix = 0;
	//for (ix = 0; ix < jlen1; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getUserName: ", "0x%02X ", (int) arg1[ix]);
	//}

	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg2, (jbyte *) arg2, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg3, (jbyte *) arg3, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg4, (jbyte *) arg4, 0);
	}

	jbyte byteUrl[] = {41,42,43,43,44};
	int sizeByteUrl = 5;

	jbyteArray data = (*env)->NewByteArray(env, sizeByteUrl);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < sizeByteUrl; i++) {
		bytes[i] = byteUrl[i];
	}

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, sizeByteUrl, bytes);

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_getvCardInfoAvatar(JNIEnv *env, jobject jObj, jbyteArray jarg1, jint jlen1, jbyteArray jarg2, jint jlen2, jbyteArray jarg3, jint jlen3) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	unsigned char *arg2 = (unsigned char *) 0 ;
	unsigned char *arg3 = (unsigned char *) 0 ;
	(void)env;
	(void)jObj;

	unsigned long long  len1;
	len1 = (unsigned long long)jlen1;
	unsigned long long  len2;
	len2 = (unsigned long long)jlen2;
	unsigned long long  len3;
	len3 = (unsigned long long)jlen3;

	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	{
		arg2 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg2, 0);
	}
	if (len3 > 0)
	{
		arg3 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg3, 0);
	}

	unsigned char *newVcard = 0;
	size_t retLength = 0;
	int retVal = 0;
	retVal = getvCardInfoAvatar(arg1, len1, arg2, len2, arg3, len3, &newVcard, &retLength);
	if (retVal < 0) {
		return NULL;
	}

	//int ix = 0;
	//for (ix = 0; ix < 100; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getvCardInfoAvatar: ", "0x%02X ", (int) newVcard[ix]);
	//}

	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg2, (jbyte *) arg2, 0);
	}
	if (len3 > 0)
	{
		(*env)->ReleaseByteArrayElements(env, jarg3, (jbyte *) arg3, 0);
	}

	jbyteArray data = (*env)->NewByteArray(env, retLength);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < retLength; i++) {
		bytes[i] = newVcard[i];
	}
	free(newVcard);

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, retLength, bytes);

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_getvCardAvatar(JNIEnv *env, jobject jObj, jbyteArray jarg1, jint jlen1) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jObj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}

	unsigned long long len1;
	len1 = (unsigned long long)jlen1;

	//int ix = 0;
	//for (ix = 0; ix < jlen1; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getvCardAvatar: ", "0x%02X ", (int) arg1[ix]);
	//}

	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	jbyte byteUrl[] = {41,42,43,43,44};
	int sizeByteUrl = 5;

	jbyteArray data = (*env)->NewByteArray(env, sizeByteUrl);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < sizeByteUrl; i++) {
		bytes[i] = byteUrl[i];
	}

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, sizeByteUrl, bytes);

	return data;

}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_getvCardPubKey(JNIEnv *env, jobject jObj, jbyteArray jarg1, jint jlen1) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jObj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}

	unsigned long long len1;
	len1 = (unsigned long long)jlen1;

	unsigned char *newPubKey = 0;
	size_t retLength = 0;
	int retValue = 0;
	retValue = getvCardPubKey(arg1, len1, &newPubKey, &retLength);
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	//int ix = 0;
	//for (ix = 0; ix < retLength; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getvCardPubKey: ", "0x%02X ", (int) newPubKey[ix]);
	//}

	jbyteArray data = (*env)->NewByteArray(env, retLength);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < retLength; i++) {
		bytes[i] = newPubKey[i];
	}
	free(newPubKey);

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, retLength, bytes);

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_getvCardpreKeys(JNIEnv *env, jobject jObj, jbyteArray jarg1, jint jlen1) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jObj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}

	unsigned long long len1;
	len1 = (unsigned long long)jlen1;

	unsigned char *newPreKey = 0;
	size_t retLength = 0;
	int retValue = 0;
	retValue = getvCardPreKeys(arg1, len1, &newPreKey, &retLength);
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	//int ix = 0;
	//for (ix = 0; ix < 200; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getvCardpreKeys: ", "0x%02X ", (int) newPreKey[ix]);
	//}
	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_getvCardpreKeys: ", "%d ", (int) retLength);

	jbyteArray data = (*env)->NewByteArray(env, retLength);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < retLength; i++) {
		bytes[i] = newPreKey[i];
	}
	free(newPreKey);

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, retLength, bytes);

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateUserFromNativeCode(JNIEnv * env, jobject jOgj, jbyteArray public_identity_key, jint public_master_key_length, jbyteArray prekey_list, jint public_prekeys_length_inp, jbyteArray random_data, jint random_data_length, jbyteArray backup_keyin, jint backup_key_lengthin) {
	jint jresult = 0;

	unsigned char *arg1 = (unsigned char *) 0 ;
	unsigned char *arg2 = (unsigned char *) 0 ;
	unsigned char *arg3 = (unsigned char *) 0 ;
	unsigned char *arg5 = (unsigned char *) 0 ;
	unsigned long long arg4;
	unsigned long long pubMasterKeyLenth;
	unsigned long long pubPreKeyLenth;
	unsigned long long backup_key_lengthtmp;
	arg4 = (unsigned long long)random_data_length;
	pubMasterKeyLenth = (unsigned long long)public_master_key_length;
	pubPreKeyLenth = (unsigned long long)public_prekeys_length_inp;
	backup_key_lengthtmp = (unsigned long long)backup_key_lengthin;

	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, public_identity_key, 0);
	}
	{
		arg3 = (unsigned char *) (*env)->GetByteArrayElements(env, random_data, 0);
	}
	{
		arg5 = (unsigned char *) (*env)->GetByteArrayElements(env, backup_keyin, 0);
	}

	unsigned char *public_prekeys = NULL;
	size_t public_prekeys_length = pubPreKeyLenth;
	unsigned char *complete_json_export = NULL;
	size_t complete_json_export_length = 0;
	//size_t public_master_key_length = crypto_box_PUBLICKEYBYTES;	//BHR:TODO
	return_status retStatus;

	//unsigned char backup_key; //BACKUP_KEY_SIZE
	unsigned char *backup_key = malloc(crypto_secretbox_KEYBYTES);
    size_t backup_key_length = backup_key_lengthtmp;
    //optional output (can be NULL)
    unsigned char **const backup;  //exports the entire library state, free after use, check if NULL before use!
    size_t backup_length = 0;
    //optional input (can be NULL)

	android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "%d ; %d ; %d", (int) backup_key_length, (int) public_prekeys_length, (int) arg4);)

	int retVal = 0;
	//int retVal = molch_create_user(arg1, &arg2, &prekey_list_length, arg3, arg4, &complete_json_export, &complete_json_export_length);
	//Last retStatus = molch_create_user(arg1, &public_prekeys, &prekey_list_length, arg3, arg4, &complete_json_export, &complete_json_export_length);
	retStatus = molch_create_user(arg1, pubMasterKeyLenth, &public_prekeys, &public_prekeys_length, backup_key, backup_key_length, &complete_json_export, &complete_json_export_length, arg3, arg4);
	if (retStatus.status != SUCCESS) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchCreateUserFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		retVal = -1;
	}

	android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "%d", (int) retStatus.status);)

	jbyteArray data = NULL;
	if (public_prekeys == NULL) {
		retVal = -1;
	}
	else {
		arg2 = (unsigned char *) (*env)->GetByteArrayElements(env, prekey_list, 0);
		jsize length = (*env)->GetArrayLength(env, prekey_list);
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "%d = %d ", (int) length, (int) public_prekeys_length);)
		if (length == public_prekeys_length) {
			jsize i;
			for (i = 0; i < length; ++i) {
				arg2[i] = public_prekeys[i];
				//__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) arg2[i]);
			}
			{
				(*env)->ReleaseByteArrayElements(env, prekey_list, (jbyte *) arg2, 0);
			}
		}
	}

	android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "next %d", (int) complete_json_export_length);)

	if (complete_json_export == NULL) {
		retVal = -1;
	}
	else if (retVal != -1){
		jbyteArray data = (*env)->NewByteArray(env, complete_json_export_length);
		if (data == NULL) {
			return NULL; //  out of memory error thrown
		}
		jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
		int i;
		for (i = 0; i < complete_json_export_length; i++) {
			bytes[i] = complete_json_export[i];
		}
		(*env)->SetByteArrayRegion(env, data, 0, complete_json_export_length, bytes);

		free(complete_json_export);
	}

	android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "%d", (int) retVal);)

	if (backup_key == NULL) {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "backup_key == NULL");)
	}
	else if (retVal != -1) {
		arg5 = (unsigned char *) (*env)->GetByteArrayElements(env, backup_keyin, 0);
		jsize length = (*env)->GetArrayLength(env, backup_keyin);
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "%d = %d ", (int) length, (int) backup_key_length);)
		if (length == backup_key_length) {
			jsize i;
			for (i = 0; i < length; ++i) {
				arg5[i] = backup_key[i];
				android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) arg5[i]);)
			}
			free(backup_key);
			{
				(*env)->ReleaseByteArrayElements(env, backup_keyin, (jbyte *) arg5, 0);
			}
		}
	}

	//int ix = 0;
	//for (ix = 0; ix < crypto_box_PUBLICKEYBYTES; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateUserFromNativeCode: ", "0x%02X ", (int) arg1[ix]);
	//}

	jresult = (jint) retVal;
	{
		(*env)->ReleaseByteArrayElements(env, public_identity_key, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, random_data, (jbyte *) arg3, 0);
	}

	return data;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchDestroyUserFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray public_identity_key, jint public_master_key_lengthin, jbyteArray jarg2) {
	jint jresult = 0;
	unsigned char *arg1 = (unsigned char *) 0 ;
	unsigned char *arg2 = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, public_identity_key, 0);
	}
	{
		arg2 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg2, 0);
	}
	unsigned long long public_master_key_length;
	public_master_key_length = (unsigned long long)public_master_key_lengthin;

	size_t json_export_length = 0;
	return_status retStatus;
	//public_master_key_length = crypto_box_PUBLICKEYBYTES;
	int retVal = 0;
	//retStatus = molch_destroy_user(arg1, &arg2, &json_export_length);
	retStatus = molch_destroy_user(arg1, public_master_key_length, &arg2, &json_export_length);

	if (retStatus.status != SUCCESS) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchDestroyUserFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		retVal = -1;
	}

	jresult = (jint) retVal;
	{
		(*env)->ReleaseByteArrayElements(env, public_identity_key, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg2, (jbyte *) arg2, 0);
	}

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
	jint jresult = 0;
	jint *jarr2;
	unsigned long long *arg2 = (unsigned long long *) 0 ;
	(void)env;
	(void)jOgj;

	if (!SWIG_JavaArrayInLong(env, &jarr2, (long **)&arg2, count)) {
		return 0;
	}

	size_t tmpCount = 0;
	unsigned char* retptr;
	return_status retStatus;
	size_t user_list_length = 0;
	int retVal = 0;
	//retStatus = molch_user_list(&retptr, &tmpCount);
	retStatus = molch_list_users(&retptr, &user_list_length, &tmpCount);
	if (retStatus.status != SUCCESS) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchUserListFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		retVal = -1;
	}
	if (arg2) {
		*arg2 = (unsigned long long) tmpCount;
	}

	int sizeByteUrl = *arg2;

	jbyteArray data = (*env)->NewByteArray(env, sizeByteUrl);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < sizeByteUrl; i++) {
		bytes[i] = retptr[i];
	}
	free(retptr);

	(*env)->SetByteArrayRegion(env, data, 0, sizeByteUrl, bytes);

	return data;
}

JNIEXPORT void JNICALL Java_de_hz1984not_crypto_Molch_molchDestroyAllUsersFromNativeCode(JNIEnv *env, jobject jOgj) {
	(void)env;
	(void)jOgj;

	molch_destroy_all_users();
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchGetMessageTypeFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2) {
	jint jresult = 0 ;
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	unsigned long long arg2 ;
	arg2 = (unsigned long long)jarg2;
	size_t tmpCount = 0;
	molch_message_type tmpResult;
	tmpResult = (int) molch_get_message_type(arg1, arg2);

	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchGetMessageTypeFromNativeCode: ", "%d\n", (int) tmpResult);

	int result = (int) tmpResult;
	jresult = (jint)result;
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	return jresult;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin, jstring jarg2, jint jarg3, jbyteArray jarg4, jint prekey_list_lengthin, jbyteArray jarg5, jint sender_public_master_key_lengthin, jbyteArray jarg6, jint receiver_public_master_key_lengthin) {
	jint jresult = 0 ;
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	char *arg2 = (char *) (char *)0 ;
	if (jarg2) {
		arg2 = (char *)(*env)->GetStringUTFChars(env, jarg2, 0);
		if (!arg2) return 0;
	}
	unsigned long long arg3 ;
	unsigned long long conversation_id_length;
	unsigned long long sender_public_master_key_length;
	unsigned long long receiver_public_master_key_length;
	unsigned long long prekey_list_length;
	arg3 = (unsigned long long)jarg3;
	conversation_id_length = (unsigned long long)conversation_id_lengthin;
	sender_public_master_key_length = (unsigned long long)sender_public_master_key_lengthin;
	receiver_public_master_key_length = (unsigned long long)receiver_public_master_key_lengthin;
	prekey_list_length = (unsigned long long)prekey_list_lengthin;

	unsigned char *arg4 = (unsigned char *) 0 ;
	{
		arg4 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg4, 0);
	}
	unsigned char *arg5 = (unsigned char *) 0 ;
	{
		arg5 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg5, 0);
	}
	unsigned char *arg6 = (unsigned char *) 0 ;
	{
		arg6 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg6, 0);
	}

	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode: ", "%s; %d\n", arg2, (int) arg3);

	jsize jlength_prekey_list_length = (*env)->GetArrayLength(env, jarg4);
	//for (int ix = 0; ix < jlength_prekey_list_length; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, ":", "0x%02X ", (int) arg4[ix]);
	//}
	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode: ", "%d\n", jlength_prekey_list_length);

	//size_t conversation_id_length = CONVERSATION_ID_SIZE;
	//size_t sender_public_master_key_length = crypto_box_PUBLICKEYBYTES;
	//size_t receiver_public_master_key_length = crypto_box_PUBLICKEYBYTES;
	unsigned char *alice_send_packet = NULL;
	size_t packet_length = 0;
	//size_t prekey_list_length = (size_t) jlength_prekey_list_length;
	unsigned char * json_export = NULL; //optional, can be NULL, exports the entire library state as json, free with sodium_free, check if NULL before use!
	size_t json_export_length = 0;
	return_status retStatus;
	int retVal = 0;
	//retStatus = molch_create_send_conversation(arg1, &alice_send_packet, &packet_length, arg2, arg3, arg4, prekey_list_length, arg5, arg6, NULL, NULL); //&json_export, &json_export_length);
	retStatus = molch_start_send_conversation(arg1, conversation_id_length, &alice_send_packet, &packet_length, arg5, sender_public_master_key_length, arg6, receiver_public_master_key_length, arg4, prekey_list_length, arg2, arg3, NULL, NULL);
	//for (int ix = 0; ix < CONVERSATION_ID_SIZE; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode: ", "0x%02X ", (int) arg1[ix]);
	//}
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}
	if (arg2) (*env)->ReleaseStringUTFChars(env, jarg2, (const char *)arg2);

	{
		(*env)->ReleaseByteArrayElements(env, jarg4, (jbyte *) arg4, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg5, (jbyte *) arg5, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg6, (jbyte *) arg6, 0);
	}

	if (retStatus.status != SUCCESS) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchCreateSendConversationFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, packet_length);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < packet_length; i++) {
		bytes[i] = alice_send_packet[i];
	}
// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, packet_length, bytes);
	free(alice_send_packet);

	if (json_export != NULL) {
		free(json_export);
	}

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin, jbyteArray jarg2, jint jarg3, jbyteArray jarg4, jint jpre_keys_lengthin, jbyteArray jarg5, jint sender_public_master_key_lengthin, jbyteArray jarg6, jint receiver_public_master_key_lengthin) {
	(void)env;
	(void)jOgj;
	unsigned char *arg1 = (unsigned char *) 0 ;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	unsigned char *arg2 = (unsigned char *) 0 ;
	{
		arg2 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg2, 0);
	}
	unsigned long long arg3 ;
	unsigned long long conversation_id_length;
	unsigned long long sender_public_master_key_length;
	unsigned long long receiver_public_master_key_length;
	arg3 = (unsigned long long)jarg3;
	conversation_id_length = (unsigned long long)conversation_id_lengthin;
	sender_public_master_key_length = (unsigned long long)sender_public_master_key_lengthin;
	receiver_public_master_key_length = (unsigned long long)receiver_public_master_key_lengthin;
	jsize jpre_keys_length = 0;
	unsigned char *arg4 = (unsigned char *) 0 ;
	{
		arg4 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg4, 0);
		jpre_keys_length = (*env)->GetArrayLength(env, jarg4);
	}
	unsigned char *arg5 = (unsigned char *) 0 ;
	{
		arg5 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg5, 0);
	}
	unsigned char *arg6 = (unsigned char *) 0 ;
	{
		arg6 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg6, 0);
	}

	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "----------------");
	//for (int ix = 0; ix < CONVERSATION_ID_SIZE; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "0x%02X ", (int) arg6[ix]);
	//}
	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "----------------");
	//for (int ix = 0; ix < 128; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "0x%02X ", (int) arg4[ix]);
	//}
	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "----------------");
	//for (int ix = 0; ix < CONVERSATION_ID_SIZE; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", "0x%02X ", (int) arg5[ix]);
	//}

	//size_t conversation_id_length = CONVERSATION_ID_SIZE;
	//size_t receiver_public_master_key_length = crypto_box_PUBLICKEYBYTES;
	//size_t sender_public_master_key_length = crypto_box_PUBLICKEYBYTES;
	unsigned char *alice_receive_packet;
	size_t alice_message_length = 0;
	size_t pre_keys_length = (size_t) jpre_keys_length;
	unsigned char *my_public_prekeys = NULL;  //arg4
	unsigned char * json_export = NULL; //optional, can be NULL, exports the entire library state as json, free with sodium_free, check if NULL before use!
	size_t json_export_length = 0;
	return_status retStatus;
	//retStatus = molch_create_receive_conversation(arg1, &alice_receive_packet, &alice_message_length, arg2, arg3, &my_public_prekeys, &pre_keys_length, arg5, arg6, &json_export, &json_export_length);
	retStatus = molch_start_receive_conversation(arg1, conversation_id_length, &my_public_prekeys, &pre_keys_length, &alice_receive_packet, &alice_message_length, arg6, receiver_public_master_key_length, arg5, sender_public_master_key_length, arg2, arg3, &json_export, &json_export_length);
	int preKeyerrorCode = 0;
	if (retStatus.status == SUCCESS) {
		if (my_public_prekeys == NULL) {
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: notNewPreKeyList;", "error: %d\n", retStatus.status);)
			preKeyerrorCode = -10;
			//return NULL;
		}
		else {
			if (jpre_keys_length == pre_keys_length) {
				int i;
				for (i = 0; i < pre_keys_length; i++) {
					arg4[i] = my_public_prekeys[i];
				}
				free(my_public_prekeys);
			}
			else {
				android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: preKeyListdifferent;", "error: %d\n", retStatus.status);)
				preKeyerrorCode = -11;
			}
		}
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg2, (jbyte *) arg2, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg5, (jbyte *) arg5, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg6, (jbyte *) arg6, 0);
	}

	if (retStatus.status != SUCCESS || preKeyerrorCode != 0) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchCreateReceiveConversationFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, alice_message_length);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < alice_message_length; i++) {
		bytes[i] = alice_receive_packet[i];
	}
	(*env)->SetByteArrayRegion(env, data, 0, alice_message_length, bytes);
	free(alice_receive_packet);

	if (json_export != NULL)
	{
		free(json_export);
	}

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode(JNIEnv *env, jobject jOgj, jstring jarg1, jint jarg2, jbyteArray jarg3, jint conversation_id_lengthin) {
	jint jresult = 0 ;
	(void)env;
	(void)jOgj;
	char *arg1 = (char *) (char *)0 ;
	if (jarg1) {
		arg1 = (char *)(*env)->GetStringUTFChars(env, jarg1, 0);
		if (!arg1) return 0;
	}
	unsigned long long arg2 ;
	unsigned long long conversation_id_length;
	arg2 = (unsigned long long)jarg2;
	conversation_id_length = (unsigned long long)conversation_id_lengthin;
	unsigned char *arg3 = (unsigned char *) 0 ;
	{
		arg3 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg3, 0);
	}

	//int ix = 0;
	//for (ix = 0; ix < CONVERSATION_ID_SIZE; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode: ", "0x%02X ", (int) arg3[ix]);
	//}
	//__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode: ", "-------");
	//for (ix = 0; ix < arg2; ix++) {
	//	__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode: ", "0x%02X ", (int) arg1[ix]);
	//}

	//size_t conversation_id_length = CONVERSATION_ID_SIZE;
	unsigned char *packet;
	size_t packet_length = 0;
	unsigned char * conversation_json_export = NULL;
	size_t json_export_conversation_length = 0;
	return_status retStatus;
	//retStatus = molch_encrypt_message(&packet, &packet_length, arg1, arg2, arg3, &conversation_json_export, &json_export_conversation_length);
	retStatus = molch_encrypt_message(&packet, &packet_length, arg3, conversation_id_length, arg1, arg2, &conversation_json_export, &json_export_conversation_length);
	if (arg1)
		(*env)->ReleaseStringUTFChars(env, jarg1, (const char *)arg1);
	{
		(*env)->ReleaseByteArrayElements(env, jarg3, (jbyte *) arg3, 0);
	}

	if (retStatus.status != SUCCESS) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchEncryptMessageFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, packet_length);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < packet_length; i++) {
		bytes[i] = packet[i];
	}
// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, packet_length, bytes);
	free(packet);

	if (conversation_json_export != NULL)
	{
		free(conversation_json_export);
	}

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchDecryptMessageFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2, jbyteArray jarg3, jint conversation_id_lengthin) {
	jint jresult = 0 ;
	(void)env;
	(void)jOgj;
	unsigned char *arg1 = (unsigned char *) 0 ;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	unsigned long long arg2 ;
	arg2 = (unsigned long long)jarg2;
	unsigned long long conversation_id_length;
	conversation_id_length = (unsigned long long)conversation_id_lengthin;
	unsigned char *arg3 = (unsigned char *) 0 ;
	{
		arg3 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg3, 0);
	}

	unsigned char *packet;
	size_t packet_length = 0;
	uint32_t receive_message_number = 0;
    uint32_t previous_receive_message_number = 0;
    //size_t conversation_id_length = CONVERSATION_ID_SIZE;
	unsigned char * conversation_json_export = NULL;
	size_t conversation_json_export_length = 0;
	return_status retStatus;
	//retStatus = molch_decrypt_message(&packet, &packet_length, arg1, arg2, arg3, &conversation_json_export, &conversation_json_export_length);
	retStatus = molch_decrypt_message(&packet, &packet_length, &receive_message_number, &previous_receive_message_number, arg3, conversation_id_length, arg1, arg2, &conversation_json_export, &conversation_json_export_length);
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}
	{
		(*env)->ReleaseByteArrayElements(env, jarg3, (jbyte *) arg3, 0);
	}

	if (retStatus.status != 0) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchDecryptMessageFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, packet_length);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < packet_length; i++) {
		bytes[i] = packet[i];
	}
	(*env)->SetByteArrayRegion(env, data, 0, packet_length, bytes);
	free(packet);

	if (conversation_json_export != NULL)
	{
		free(conversation_json_export);
	}

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchEndConversationFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint conversation_id_lengthin) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	int i;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	unsigned long long conversation_id_length;
	conversation_id_length = (unsigned long long)conversation_id_lengthin;

	//size_t conversation_id_length = CONVERSATION_ID_SIZE;
    size_t json_export_length = 0;
    unsigned char * json_export = 0;
	//molch_end_conversation(arg1, &json_export, &json_export_length);
	molch_end_conversation(arg1, conversation_id_length, &json_export, &json_export_length);
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	jbyteArray data = 0;
	if (json_export_length != 0) {
		data = (*env)->NewByteArray(env, json_export_length);
		if (data == NULL) {
			return NULL; //  out of memory error thrown
		}

		// creat bytes from byteUrl
		jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
		int i;
		for (i = 0; i < json_export_length; i++) {
			bytes[i] = json_export[i];
		}

		// move from the temp structure to the java structure
		(*env)->SetByteArrayRegion(env, data, 0, json_export_length, bytes);
	}

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2) {
	unsigned char *arg1 = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
	}
	unsigned long long arg2 ;
	arg2 = (unsigned long long)jarg2;

	size_t conversation_list_length = 0;
	size_t number_of_conversations = 0;
	unsigned char *conversation_list = NULL;

	android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode: ", "arg2: %d\n", (int) arg2);)

	return_status retStatus;
	retStatus = molch_list_conversations(&conversation_list, &conversation_list_length, &number_of_conversations, arg1, arg2);
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
	}

	android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode: ", "retStatus.status: %d; number_of_conversations: %d\n", (int) retStatus.status, (int) number_of_conversations);)

	if (conversation_list == NULL || number_of_conversations <= 0 || retStatus.status != 0) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchListConversationsFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, arg2);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < arg2; i++) {
		bytes[i] = conversation_list[(number_of_conversations - 1) + i];
	}

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, arg2, bytes);

	return data;
}

JNIEXPORT jbyteArray JNICALL Java_de_hz1984not_crypto_Molch_molchJsonExportFromNativeCode(JNIEnv *env, jobject jOgj) {
	jint *jarr1;
	(void)env;
	(void)jOgj;

	size_t imported_json_length;
	return_status retStatus;
	unsigned char *imported_json;
	//retStatus = molch_json_export(&imported_json, &imported_json_length);
	retStatus = molch_export(&imported_json, &imported_json_length);
	if (imported_json == NULL || retStatus.status != 0) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchJsonExportFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
		return NULL;
	}

	jbyteArray data = (*env)->NewByteArray(env, imported_json_length);
	if (data == NULL) {
		return NULL; //  out of memory error thrown
	}

// creat bytes from byteUrl
	jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
	int i;
	for (i = 0; i < imported_json_length; i++) {
		bytes[i] = imported_json[i];
	}

// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, data, 0, imported_json_length, bytes);

	return data;
}

JNIEXPORT jint JNICALL Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode(JNIEnv *env, jobject jOgj, jbyteArray jarg1, jint jarg2, jbyteArray jnewbackupkeyin, jint jnewbackupkeyin_length, jbyteArray joldbackupkeyin, jint joldbackupkeyin_length) {
	jint jresult = 0 ;
	unsigned char *arg1 = (unsigned char *) 0 ;
	unsigned char *newbackupkey = (unsigned char *) 0 ;
	unsigned char *oldbackupkey = (unsigned char *) 0 ;
	(void)env;
	(void)jOgj;
	{
		arg1 = (unsigned char *) (*env)->GetByteArrayElements(env, jarg1, 0);
		newbackupkey = (unsigned char *) (*env)->GetByteArrayElements(env, jnewbackupkeyin, 0);
		oldbackupkey = (unsigned char *) (*env)->GetByteArrayElements(env, joldbackupkeyin, 0);
	}

	unsigned long long arg2;
	arg2 = (unsigned long long)jarg2;
	unsigned long long newbackupkeyin_length;
	newbackupkeyin_length = (unsigned long long)jnewbackupkeyin_length;
	unsigned long long oldbackupkeyin_length;
	oldbackupkeyin_length = (unsigned long long)joldbackupkeyin_length;

	for (int i = 0; i < newbackupkeyin_length; ++i) {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) newbackupkey[i]);)
	}
	android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode: ", "arg2: %d; %d; %d\n", (int) arg2, (int) newbackupkeyin_length, (int) oldbackupkeyin_length);)
	for (int i = 0; i < oldbackupkeyin_length; ++i) {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) oldbackupkey[i]);)
	}

	return_status retStatus;
	//retStatus = molch_json_import(arg1, arg2);
	retStatus = molch_import(newbackupkey, newbackupkeyin_length, arg1, arg2, oldbackupkey, oldbackupkeyin_length);
	android_only(__android_log_print(ANDROID_LOG_DEBUG, "Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode: ", "retStatus.status: %d;\n", (int) retStatus.status);)
	jresult = (jint) retStatus.status;
	{
		(*env)->ReleaseByteArrayElements(env, jarg1, (jbyte *) arg1, 0);
		(*env)->ReleaseByteArrayElements(env, jnewbackupkeyin, (jbyte *) newbackupkey, 0);
		(*env)->ReleaseByteArrayElements(env, joldbackupkeyin, (jbyte *) oldbackupkey, 0);
	}

	for (int i = 0; i < newbackupkeyin_length; ++i) {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, ": ", "0x%02X ", (int) newbackupkey[i]);)
	}

	if (retStatus.status != 0) {
		print_info_error("Java_de_hz1984not_crypto_Molch_molchJsonImportFromNativeCode: ", retStatus);
		molch_destroy_return_status(&retStatus);
	}

	return jresult;
}




