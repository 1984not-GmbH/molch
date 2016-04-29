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
or run the script `ci/build.sh`.

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
or run the script `ci/clang-static-analysis.sh`.

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

Want to help?
-------------------
Take a look at the file `CONTRIBUTING`. And look for GitHub Issues with the `help wanted` label.

license
-------
This library is licensed under the LGPLv2.1.
