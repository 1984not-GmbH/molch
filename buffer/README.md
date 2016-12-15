molch-buffer
============

[![Travis Build Status](https://travis-ci.org/FSMaxB/molch-buffer.svg?branch=master)](https://travis-ci.org/FSMaxB/molch-buffer)

This is a buffer datatype created for the molch crypto library, see https://github.com/FSMaxB/molch. It uses functions provided by libsodium.

molch-buffer combines a buffer datatype (simple struct containing a pointer to an array and it's length). And helper functions to work with those buffers.
```c
typedef struct buffer_t {
	const size_t buffer_length;
	size_t content_length;
	/*This position can be used by parsers etc. to keep track of the position
	it is initialized with a value of 0.*/
	size_t position;
	bool readonly; //if set, this buffer shouldn't be written to.
	unsigned char * const content;
} buffer_t;
```

To use it just put `buffer.h` and `buffer.c` into your project. You also need to tell the linker to link it against libsodium.

molch-buffer is licensed under the ISC license.
