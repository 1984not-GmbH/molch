molch
=====

[![Travis Build Status](https://travis-ci.org/FSMaxB/molch.svg?branch=master)](https://travis-ci.org/FSMaxB/molch)
[![Join the chat at https://gitter.im/FSMaxB/molch](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/FSMaxB/molch?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

An implementation of the axolotl ratchet (https://github.com/trevp/axolotl/wiki) based on libsodium.

**WARNING: THIS SOFTWARE ISN'T READY YET. DON'T USE IT!**

status
------
There's still a long way to go.

Currently implemented:
* HKDF (HMAC based Key Derivation Function), see RFC 5869
* ECDH (Elliptic Curve Diffie Hellman key exchange)
* Triple Diffie Hellman (Used to derive a shared secret from identity and ephemeral keys)
  - H(ECDH(A,B0)||ECDH(A0,B)||ECDH(A0,B0))
  - Where A and B are the identity keys and A0 and B0 the ephemeral keys of Alice and Bob
* Datatype and helper functions for handling buffers that know their length.

Axolotl specific:
* Chain key derivation (derive next chain key from previous one, CK = HMAC-Hash(CK, 0x01))
* Message key derivatin (derive message key from chain key, MK = HMACH-Hash(MK, 0x00))
* Symmetrically encrypt a message and authenticate header.
  - `header_length (1Byte) || header || nonce || MAC(Header + nonce + header_length) || CIPHERTEXT (crypto_secretbox)`
* double linked list for storing message keys that haven't been used yet
* Ratchet (deriving root, chain and message keys, no message decryption and authentication yet)

how to build
------------
This has been tested on GNU/Linux and Mac OS X.

First make sure `libsodium` and `cmake` are installed.

Then do the following:
```
$ mkdir build #make build directory
$ cd build    #change into it
$ cmake ..    #run cmake (only required once)
$ make        #finally compile the software
```
or run the script `run-build.sh` from the projects root directory.

Run the tests (you need to have valgrind installed):
```
$ cd build
$ make test
```

Run the static analysis (you need clang and clangs static analyzer):
```
$ mkdir static-analysis
$ cd static-analysis
$ scan-build cmake ..
$ scan-build make
```
or run the script `run-static-analysis.sh` from the projects root directory.

size of a packet
----------------
NOTE: This may be subject to change.

```
packet (>=362) = {
  protocol_version(1),
  packet_type(1),
  header_length(1),
  header_nonce(crypto_aead_chacha20poly1305_NPUBBYTES = 8),
  header (64) {
      axolotl_header(crypto_box_PUBLICKEYBYTES + 8 = 40) {
        sender_public_ephemeral (crypto_box_PUBLICKEYBYTES = 32),
        message_number (4),
        previous_message_number (4)
      }
      message_nonce(crypto_secretbox_NONCEBYTES = 24)
  },
  header_and_additional_data_MAC(crypto_aead_chacha20poly1305_ABYTES = 16),
  authenticated_encrypted_message (>=271) {
      message(>=255),
      MAC(crypto_secretbox_MACBYTES = 16)
  }
}

To be precise: 362 + n*255 with n = 0, 1, 2, ...
```

If the message length exceeds 254 Bytes, you have to add another 255 bytes because of the padding. The length of the padded message is always the following:

`ceil(raw_message_length / 255) * 255`

license
-------
This library is licensed under the LGPLv2.1.
