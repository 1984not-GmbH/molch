/* 1984notlib, an implementation for 1984notApp
 *  Copyright (C) 2016  1984not Security GmbH
 *
 *
 * */

#include <stdbool.h>

#ifndef LIB_1984NOTLIB_H
#define LIB_1984NOTLIB_H

int getvCardInfoAvatar(unsigned char * public_identity_key, const size_t publicLength, unsigned char * preKeyList, const size_t preKeysLength, unsigned char * avatarData, const size_t avatarLength, unsigned char ** newVcard, size_t *retLength);
int getvCardPubKey(unsigned char * avatarData, const size_t avatarLength, unsigned char ** newpubKey, size_t *retLength);
int getvCardPreKeys(unsigned char * avatarData, const size_t avatarLength, unsigned char ** newpubKey, size_t *retLength);

#endif
