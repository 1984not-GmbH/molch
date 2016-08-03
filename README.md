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

You might also have to run `git submodule update` when changing branches or after pulling in new changes.

dependencies
--------------------
Molch depends on the following:
* [libsodium](https://github.com/jedisct1/libsodium)
* [protobuf-c](https://github.com/protobuf-c/protobuf-c)
* CMake (build and tests)
* C-Compiler (build)
* Clang Static Analyzer (tests)
* Address Sanitizer (tests)
* Undefined Behavior Sanitizer (tests)
* [Valgrind](http://valgrind.org/)
* [Lua](https://www.lua.org/) (optional, for Lua-Bindings)
* [Swig](http://swig.org/) (optional, for Lua-Bindings)
* [Doxygen](https://www.stack.nl/~dimitri/doxygen/) (optional, documentation)
* [Graphviz](http://graphviz.org/) (optional, documentation)

On Ubuntu:
```
sudo apt-get install libsodium18 libsodium-dev libprotobuf-c-dev libprotobuf-c1 libprotobuf-c1-dbg libprotobuf9v5:armhf protobuf-c-compiler cmake clang libubsan0 libasan0 libasan1 libasan2 valgrind liblua5.3 lua5.3 liblua5.3-dev swig doxygen graphviz
```

On Arch:
```
sudo pacman -S cmake clang-analyzer libsodium valgrind swig lua doxygen graphviz protobuf-c
```

On Max OS X (via homebrew):
```
brew install libsodium valgrind swig lua graphviz doxygen protobuf-c
```

supported platforms
-------------------
Molch is constantly tested on the following platforms:

| processor        | os                          |
|:-----------------|:----------------------------|
| x86_64           | Archlinux                   |
| i686             | Archlinux                   |
| ARMv7hf          | Ubuntu 16.04 (Xenial Xerus) |
| PowerPC Apple G4 | Debian Stretch (Testing)    |
| x86_64           | Mac OS X 10.9 Mavericks     |

how to build
------------
Run the script `ci/test.sh` from the project root to build Molch and run the tests.

Run the script `ci/clang-static-analysis.sh` from the project root to run static analysis.

how to generate traces for debugging
------------------------------------
```
$ mkdir tracing
$ cd tracing
$ cmake .. -DCMAKE_BUILD_TYPE=Debug -DTRACING=On
$ make
```

Now, when you run one of the tests (those are located at `tracing/test/`), it will generate a file `trace.out` and print all function calls to stdout.

You can postprocess this tracing output with `test/trace.lua`, pass it the path of `trace.out`, or the path to a saved output of the test and it will pretty-print the trace. It can also filter out function calls to make things easier to read, see it's source code for more details.

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

> ISC License
>
> Copyright (C) 2015-2016 1984not Security GmbH
>
> Author: Max Bruckner (FSMaxB)
>
> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
> WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
> ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
> ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
> OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
