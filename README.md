molch
=====

[![Travis Build Status](https://travis-ci.org/1984not-GmbH/molch.svg?branch=master)](https://travis-ci.org/1984not-GmbH/molch)
[![Coverity Scan Build](https://scan.coverity.com/projects/6421/badge.svg)](https://scan.coverity.com/projects/6421)
[![Join the chat at https://gitter.im/FSMaxB/molch](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/FSMaxB/molch?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

An implementation of the axolotl ratchet (https://github.com/trevp/axolotl/wiki) based on libsodium.

**WARNING: THIS SOFTWARE ISN'T READY YET. DON'T USE IT!**

how to get the code
-------------------
After cloning the repository, the git submodules have to be initialised and updated:
```
$ git clone https://github.com/FSMaxB/molch
$ git submodule update --init --recursive
```

dependencies
--------------------
Molch depends on the following:
* [libsodium](https://github.com/jedisct1/libsodium)
* [protobuf-c](https://github.com/protobuf-c/protobuf-c)
* Meson (build and tests)
* C-Compiler (build)
* C++-Compiler (build)
* Clang Static Analyzer (tests)
* Address Sanitizer (tests)
* Undefined Behavior Sanitizer (tests)
* [Valgrind](http://valgrind.org/)
* [Lua](https://www.lua.org/) (optional, for Lua-Bindings)
* [Swig](http://swig.org/) (optional, for Lua-Bindings)
* [Doxygen](https://www.stack.nl/~dimitri/doxygen/) (optional, documentation)
* [Graphviz](http://graphviz.org/) (optional, documentation)
* [Android-NDK](https://developer.android.com/ndk/index.html) (optional, for Android builds)

On Ubuntu:
```
sudo apt-get install libsodium18 libsodium-dev libprotobuf-c-dev libprotobuf-c1 libprotobuf-c1-dbg libprotobuf9v5:armhf protobuf-c-compiler clang libubsan0 libasan0 libasan1 libasan2 valgrind liblua5.3 lua5.3 liblua5.3-dev swig doxygen graphviz meson
```

On Arch:
```
sudo pacman -S clang-analyzer libsodium valgrind swig lua doxygen graphviz protobuf-c meson
```

On Max OS X (via homebrew):
```
brew install libsodium valgrind swig lua graphviz doxygen protobuf-c meson
```

supported platforms
-------------------
Molch is constantly tested on the following platforms:

| processor        | os                          |
|:-----------------|:----------------------------|
| x86_64           | Archlinux                   |
| i686             | Ubuntu 16.04                |
| ARMv7hf          | Archlinux ARM               |
| AArch64          | Archlinux ARM               |
| PowerPC Apple G4 | Gentoo                      |
| x86_64           | Mac OS X 10.11 El Capitan   |

how to build
------------

To build Molch run the script `release.sh` from the project root.

To run all tests, run `./run-ci.sh` from the project root.
Or you can run the scripts separately:
* `test.sh`: For normal build and tests with and without valgrind
* `sanitizers.sh`: To build and run with AddressSanitizer and UndefinedBehaviorSanitizer
* `static-analysis.`: To run clang static analyzer
* `doxygen.sh`: To create the documentation

format of a packet
----------------
Molch uses [Googles Protocol Buffers](https://developers.google.com/protocol-buffers/) via the [Protobuf-C](https://github.com/protobuf-c/protobuf-c) library. You can find the protocol descriptions in `lib/protobuf`.

cryptography
------------
This is a brief non-complete overview of the cryptographic primitives used by molch. A detailed description of what molch does cryptographically is only provided by its source code at the moment.

Molch uses only primitives implemented by [libsodium](https://github.com/jedisct1/libsodium).

**Key derivation:** Blake2b
**Header encryption:** Xsalsa20 with Poly1305 MAC
**Message encryption:** XSalsa20 with Poly1305 MAC
**Signing keys (used to sign prekeys and the identity key):** Ed25519
**Other keypairs:** X25519
**Key exchange:** ECDH with X25519

Molch allows you to mix in a low entropy random source to the creation of signing and identity keypairs. In this case, the low entropy random source is used as input to Argon2i and the output xored with high entropy random numbers provided by the operating system.

Want to help?
-------------------
Take a look at the file `CONTRIBUTING`. And look for GitHub Issues with the `help wanted` label.

license
-------

This library is licensed under the ISC license.

More about information can be found in the file `LICENSE.md`.
