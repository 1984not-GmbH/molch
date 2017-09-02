contribution guidelines
=======================

coding style
----------
Take a look at existing code to see how the code style looks like. Some noteworthy things:
* always use tabs for indentation
* split function calls / function definitions into multiple lines if they get too long (see the code for examples)
* no one line ifs/fors/whiles ..., every one of those must use two curly braces

APIs
----
These are guidelines on how to structure APIs, this applies not only to the public API, but also to internal APIs between components.

Function parameters:
* output first, followed by input
* public key first, then private key
* optional parameters at the end (optional outputs **after** regular inputs)
* inputs/outputs that aren't allocated by the function get passed as Molch::span

Naming conventions:
* Functions:
  - `molch_end_conversation` instead of `molch_conversation_end` (verb first)
  - but start with the 'class' that the function belongs to (`molch` in the example above)

coding practices
----------------
* make as much `const` as possible, including pointers (e.g. `const buffer_t * const buffer`)
* don't rely on undefined behavior
* declare variables as locally as possible, not at the beginning of a function but only once they are needed
* use `nullptr` for null pointers and explicitly check `pointer == nullptr` in conditions (this makes code much more readable and makes the programmer's intent clearer)
* AAA (Almost Always Auto): Use the `auto` keyword
* Use initializer lists where possible
* Use RAII (Resource Acquisition Is Initialization) everywhere!
* Always pass by reference if possible
* Use `gsl::byte` for binary data
* Use `byte_to_uchar` and `uchar_to_byte` to convert between `unsigned char*` and `gsl::byte*`
* Use `gsl::narrow` for integer conversions. If you know it cannot fail, you can use `gsl::narrow_cast` (no runtime overhead).

other practices
---------------
* document every new function with doxygen doc comments. Functions that are also in the header are only documented in the header file.
* use a layer based approach (function calls / access to data structures is only done top down, not the other way round), the functions that are called mustn't know by whom they are called etc.
* make sure to always overwrite memory locations that held confidential data with zeroes afterwards using sodium_memzero
  * `Buffer` does this automatically, other things to help: `SodiumAllocator`/`SodiumDeleter`, `autozero`
* if possible, always work with `Molch::span`
* write tests for everything you do
  - if you're modifying existing files, just add your test to the appropriate file in the `test` directory
  - if you're creating new files, add a new test file in the `test` directory and add it to `test/CMakeLists.txt`
* add `__attribute__((warn_unused_result))` to functions that return error codes or pointers to heap allocated memory
* Follow the CPP Core Guidelines (except use `size_t` for sizes, not a signed integer type)

git usage
---------
* make small, concise commits, that only do one thing
* write explanatory commit messages
* every commit has to compile **and** pass the tests
