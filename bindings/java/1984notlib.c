/* 1984notlib, an implementation for 1984notApp
 *  Copyright (C) 2016  1984not Security GmbH
 *
 *
 * */

#include <string.h>
#include <assert.h>
#include <alloca.h>
#ifdef __ANDROID__
#include <android/log.h>
#define android_only(code) code
#else
#define android_only(code)
#endif

#include "1984notlib.h"
#include "molch/constants.h"

#define INFO_DATA_LENGTH 3
#define INFO_PUB_KEY_LEN 5
#define INFO_PRE_KEYS_LENGTH 5

/*
 * Determine the current endianness at runtime.
 */
static bool endianness_is_little_endian() {
	const uint16_t number = 0x1;
	const unsigned char* const number_pointer = (const unsigned char*)&number;
	return (number_pointer[0] == 0x1);
}

int getvCardInfoAvatar(unsigned char * public_identity_key, const size_t publicLength, unsigned char * preKeyList, const size_t preKeysLength, unsigned char * avatarData, const size_t avatarLength, unsigned char ** newVcard, size_t *retLength) {
	unsigned char infoPubKey[INFO_PUB_KEY_LEN] = {42,0,42,0,42};
	unsigned char infoPreKeys[INFO_PRE_KEYS_LENGTH] = {0,42,0,42,0};

	*retLength = INFO_PUB_KEY_LEN + publicLength + INFO_PRE_KEYS_LENGTH + preKeysLength + avatarLength;
	android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar: ", "%zu;", *retLength);)

	*newVcard = malloc(*retLength);
	unsigned short tmpLength = (unsigned short) publicLength;
	if (endianness_is_little_endian()) {
		memcpy(&infoPubKey[INFO_DATA_LENGTH], &tmpLength, sizeof(tmpLength));
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
	} else {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_big_endian_todo: ", "%d;", tmpLength);) //BHR:TODO 22032016
	}
	if (tmpLength == 0) {
		return -1;
	}

	tmpLength = (unsigned short) preKeysLength;
	if (endianness_is_little_endian()) {
		memcpy(&infoPreKeys[INFO_DATA_LENGTH], &tmpLength, sizeof(tmpLength));
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
	} else {
		android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_big_endian_todo: ", "%d;", tmpLength);) //BHR:TODO 22032016
	}

	if (avatarLength > 0) {
		memcpy(*newVcard, &infoPubKey[0], INFO_PUB_KEY_LEN);
		memcpy(*newVcard + INFO_PUB_KEY_LEN, public_identity_key, publicLength);
		memcpy(*newVcard + INFO_PUB_KEY_LEN + publicLength, &infoPreKeys[0], INFO_PRE_KEYS_LENGTH);
		memcpy(*newVcard + INFO_PUB_KEY_LEN + publicLength + INFO_PRE_KEYS_LENGTH, preKeyList, preKeysLength);
		memcpy(*newVcard + INFO_PUB_KEY_LEN + publicLength + INFO_PRE_KEYS_LENGTH + preKeysLength, avatarData, avatarLength);
	}
	else {
		memcpy(*newVcard, &infoPubKey[0], INFO_PUB_KEY_LEN);
		memcpy(*newVcard + INFO_PUB_KEY_LEN, public_identity_key, publicLength);
		memcpy(*newVcard + INFO_PUB_KEY_LEN + publicLength, &infoPreKeys[0], INFO_PRE_KEYS_LENGTH);
		memcpy(*newVcard + INFO_PUB_KEY_LEN + publicLength + INFO_PRE_KEYS_LENGTH, preKeyList, preKeysLength);
	}

	return 0;
}

int getvCardPubKey(unsigned char * avatarData, const size_t avatarLength, unsigned char ** newpubKey, size_t *retLength) {
	unsigned char infoPubKey[INFO_PUB_KEY_LEN] = {42,0,42,0,42};

	if (avatarLength > INFO_PUB_KEY_LEN) {
		memcpy(infoPubKey, avatarData, INFO_PUB_KEY_LEN);
		unsigned short tmpLength = 0;
		if (endianness_is_little_endian()) {
			memcpy(&tmpLength, &infoPubKey[INFO_DATA_LENGTH], sizeof(tmpLength));
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
		} else {
			//if already big endian, just copy
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPubKey_big_endian_todo: ", "%d; %zu", tmpLength, sizeof(tmpLength));) //BHR:TODO 22032016
		}
		if (tmpLength < SIZE_MAX && tmpLength < (avatarLength + INFO_PUB_KEY_LEN)) {
			*newpubKey = malloc(tmpLength);
			memcpy(*newpubKey, &avatarData[INFO_PUB_KEY_LEN], tmpLength);
			*retLength = tmpLength;
		}
		else {
			return -2;
		}
    }
	else {
		return -1;
	}
	return 0;
}

int getvCardPreKeys(unsigned char * avatarData, const size_t avatarLength, unsigned char ** newpreKeys, size_t *retLength) {
	unsigned char infoPubKey[INFO_PUB_KEY_LEN] = {42,0,42,0,42};
	unsigned char infoPreKeys[INFO_PRE_KEYS_LENGTH] = {0,42,0,42,0};

	if (avatarLength > INFO_PRE_KEYS_LENGTH) {
		memcpy(infoPubKey, avatarData, INFO_PUB_KEY_LEN);
		unsigned short tmpLengthPubKey = 0;
		if (endianness_is_little_endian()) {
			memcpy(&tmpLengthPubKey, &infoPubKey[INFO_DATA_LENGTH], sizeof(tmpLengthPubKey));
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLengthPubKey);)
		} else {
			//if already big endian, just copy
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys_big_endian_todo: ", "%d;", tmpLengthPubKey);) //BHR:TODO 22032016
		}

		int startPreKeys = INFO_PUB_KEY_LEN + tmpLengthPubKey;
		memcpy(infoPreKeys, avatarData + startPreKeys, INFO_PRE_KEYS_LENGTH);
		unsigned short tmpLength = 0;
		if (endianness_is_little_endian()) {
			memcpy(&tmpLength, &infoPreKeys[INFO_DATA_LENGTH], sizeof(tmpLength));
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardInfoAvatar_little_endian: ", "%d;", tmpLength);)
		} else {
			//if already big endian, just copy
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys_big_endian_todo: ", "%d;", tmpLength);) //BHR:TODO 22032016
		}
		if (tmpLength < SIZE_MAX && tmpLengthPubKey < SIZE_MAX && tmpLength < avatarLength && tmpLengthPubKey < avatarLength) {
			android_only(__android_log_print(ANDROID_LOG_DEBUG, "getvCardPreKeys: ", "%d; %d ", (int) tmpLength, (int) tmpLengthPubKey);)
			*retLength = tmpLength;
			*newpreKeys = malloc(*retLength);
			memcpy(*newpreKeys, &avatarData[INFO_PUB_KEY_LEN + tmpLengthPubKey + INFO_PRE_KEYS_LENGTH], *retLength);
		}
		else {
			return -2;
		}
	}
	else {
		return -1;
	}
	return 0;
}
