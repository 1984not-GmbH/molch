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

license
-------
This library is licensed under the LGPLv2.1.
