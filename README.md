molch
=====

An implementation of the axolotl ratchet (https://github.com/trevp/axolotl/wiki) based on libsodium.

**WARNING:** This software hasn't been reviewed by a cryptographer and it's not in a state yet that I myself recommend using it at that point.

status
------
There's still a long way to go.

Currently implemented:
* HKDF (HMAC based Key Derivation Function), see RFC 5869
* ECDH (Elliptic Curve Diffie Hellman key exchange)
* Triple Diffie Hellman (Used to derive a shared secret from identity and ephemeral keys)
  - H(ECDH(A,B0)||ECDH(A0,B)||ECDH(A0,B0))
  - Where A and B are the identity keys and A0 and B0 the ephemeral keys of Alice and Bob

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
header length (1)
+ header (42) {
    version_info (2)
    + public_ephemeral_key (32)
    + message_counter (4)
    + previous_message_counter (4)
}
+ crypto_secretbox_NONCEBYTES (24)
+ crypto_onetimeauth_BYTES (16)
+ message (>=255)
+ crypto_secretbox_MACBYTES (16)
>= 354 Bytes
```

If the message length exceeds 255 Bytes, you have to add another 255 bytes because of the padding. The length of the padded message is always the following:

`ceil(raw_message_length / 255) * 255`

license
-------
This library is licensed under the LGPLv2.1.
