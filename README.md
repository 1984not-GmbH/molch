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


license
-------
This library is licensed under the LGPLv2.1.
