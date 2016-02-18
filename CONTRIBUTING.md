contribution guidelines
=======================

code style
----------
Take a look at existing code to see how the code style looks like. Some noteworthy things:
* always use tabs for indentation
* split function calls / function definitions into multiple lines if they get too long (see the code for examples)
* no one line ifs/fors/whiles ..., every one of those must use two curly braces

coding practices
----------------
* make as much `const` as possible, including pointers (e.g. `const buffer_t * const buffer`)
* don't rely on undefined behavior
* declare variables as locally as possible, not at the beginning of a function but only once they are needed
* use `NULL` for null pointers and explicitly check `pointer == NULL` in conditions (this makes code much more readable and makes the programmer's intent clearer)

other practices
---------------
* use a layer based approach (function calls / access to data structures is only done top down, not the other way round), the functions that are called mustn't know by whom they are called etc.
* don't use `buffer_create` to allocate buffers, use `buffer_create_on_heap` instead. There's still old code using `buffer_create`, but don't introduce new one
* deallocate those buffers with `buffer_destroy_from_heap`, this ensures, that it get's zeroed out properly
* if possible, always work with buffers that know their length (not `char *`)
* write tests for everything you do
  - if you're modifying existing files, just add your test to the appropriate file in the `test` directory
  - if you're creating new files, add a new test file in the `test` directory and add it to `test/CMakeLists.txt`
* add `__attribute__((warn_unused_result))` to functions that return error codes or pointers to heap allocated memory
* ensure that all resources are freed once you leave a function (even when errors occur)
* make sure that every test includes `tracing.h`

git usage
---------
* make small, concise commits, that only do one thing
* write explanatory commit messages
* every commit has to compile **and** pass the tests
