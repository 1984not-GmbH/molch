+++
title = "-- Now what happens?"
description = ""
weight = 28
+++

Let us run the code from the previous page:

```
ned@lyta:~/outcome/build_posix$ bin/outcome-snippets_error_code_enums2
Exception thrown was failure1
ned@lyta:~/outcome/build_posix$
```

Ah so now we are throwing a C++ exception on no-value observation! This
is because we registered our error code enum with the C++ standard library
and in so doing, we also told the standard library how our error code
interacts with `std::error_code` and thus `std::system_error`.

Outcome's default action when no-value observing a `result` or `outcome`
with a `EC` type where some ADL discovered free function `make_error_code(EC)`
returning a `std::error_code` exists[^1], is to throw a 
`std::system_error(make_error_code(.error()))`. This is how the `failure_info`
custom `EC` type was annotated to be treated as a `std::error_code` in the
[previous section of the tutorial](../../payload/copy_file2), this is the exact
same mechanism[^2].

So above, because `.error()`
is set to `err::failure1`, the free function we defined `make_error_code(err)`
converts that into a `std::error_code`, and from that the `std::system_error`
is constructed and thrown during a no-value value observation.

On catching a `std::exception`, we print the `what()` which this particular
standard library implementation (libstdc++) has chosen to set to `error_code::message()`.

[^1]: `trait::has_error_code<EC>` determines this.

[^2]: One only needs to additionally define the `throw_as_system_error_with_payload()` free function if type `EC` does not have `std::is_error_code_enum<EC>` nor `std::is_error_condition_enum<EC>` defined as true.