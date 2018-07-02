+++
title = "Inspecting result<T, EC>"
description = ""
weight = 20
tags = ["nodiscard", "value", "error", "try"]
+++

Suppose we will be writing function `print_half` that takes an integral number (however big) represented as an `std::string` and outputs a number which is twice smaller:

{{% snippet "using_result.cpp" "half_decl" %}}

Type `result<void>` means that there is no value to be retuned upon success, but that the operation might still fail, and we may be interested in inspecting the cause of the failure. Class template `result<>` is declared with attribute `[[nodiscard]]`, which means compiler will warn you if you forget to inspect the returned object (in C++ 17 or later).

The implementation will do the following: if the integral number can be represnted by an `int`, we will convert to `int` and use its arithmetical operations. If the number is too large, we will fall back to using a custom `BigInt` implementation that needs to allocate memory. In the implementation we will use function `convert` defined in the previous section.

{{% snippet "using_result.cpp" "half_impl" %}}

#1. You test if `result<>` object represents a successful operation with contextual conversion to `bool`.

#2. Function `.value()` extracts the successfully returned `BigInt`.

#3. Function `.error()` allows you to inspect the error sub-object, representing information about the reason for failure.

#4. Macro `OUTCOME_TRY` represents a control statement. It implies that the function call in the second argument returns a `result<>`. It is defined as:

{{% snippet "using_result.cpp" "from_string" %}}

   Our control statement means: if `fromString` returned failure, this same error information should be returned from `print_half`, even though the type of `result<>` is different. If `fromString` returned success, we create  variable `i` of type `int` with the value returned from `fromString`. If control goes to subsequent line, it means `fromString` succeeded and variable of type `int` is in scope.

#5. In the return statement we extract the error information and use it to initialize the return value from `print_half`. We could have written `return r.error();` instead,
    and it would have the same effect, but it would not work if we were using `outcome<>` instead of `result<>` -- this will be covered later.

#6. Function `success()` returns an object of type `success<void>` representing success. This is implicitly converted by
all `result` and `outcome` types into a successful return, default constructing any `T` if necessary.
