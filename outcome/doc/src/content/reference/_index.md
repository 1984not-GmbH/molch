+++
title = "API reference"
weight = 20
+++
# Project index

  - [`CXX_DECLARE_RESULT`](result_c#standardese-CXX_DECLARE_RESULT) &mdash; Declares a C struct representation of `result<R, S>`.

  - [`CXX_DECLARE_RESULT_EC`](result_c#standardese-CXX_DECLARE_RESULT_EC) &mdash; Declares a C struct representation of `result<R, std::error_code>`.

  - [`CXX_RESULT`](result_c#standardese-CXX_RESULT) &mdash; A reference to a previously declared struct by `CXX_DECLARE_RESULT(R, RD, S, SD)`

  - [`CXX_RESULT_EC`](result_c#standardese-CXX_RESULT_EC) &mdash; A reference to a previously declared struct by `CXX_DECLARE_RESULT_EC(R, RD)`

  - [`CXX_RESULT_ERROR`](result_c#standardese-CXX_RESULT_ERROR) &mdash; C11 generic selecting a result struct’s `error` or `code` integer member.

  - [`CXX_RESULT_ERROR_IS_ERRNO`](result_c#standardese-CXX_RESULT_ERROR_IS_ERRNO) &mdash; True if a result struct’s `error` or `code` is an `errno` domain code suitable for setting `errno` with.

  - [`CXX_RESULT_HAS_ERROR`](result_c#standardese-CXX_RESULT_HAS_ERROR) &mdash; True if a result struct has a valid error

  - [`CXX_RESULT_HAS_VALUE`](result_c#standardese-CXX_RESULT_HAS_VALUE) &mdash; True if a result struct has a valid value

  - [`CXX_RESULT_SET_ERRNO`](result_c#standardese-CXX_RESULT_SET_ERRNO) &mdash; Convenience macro setting `errno` to a result struct’s `errno` compatible error if present, or `EAGAIN` if errored but incompatible.

  - [`OUTCOME_TRY`](try#standardese-OUTCOME_TRY) &mdash; If the outcome returned by expression … is not valued, propagate any failure by immediately returning that failure immediately, else set *v* to the unwrapped value.

  - [`OUTCOME_TRYV`](try#standardese-OUTCOME_TRYV) &mdash; If the outcome returned by expression … is not valued, propagate any failure by immediately returning that failure state immediately

  - [`OUTCOME_TRYX`](try#standardese-OUTCOME_TRYX) &mdash; If the outcome returned by expression … is not valued, propagate any failure by immediately returning that failure state immediately, else become the unwrapped value as an expression. This makes `OUTCOME_TRYX(expr)` an expression which can be used exactly like the `try` operator in other languages.

  - [`cxx_error_code`](result_c#standardese-cxx_error_code) &mdash; A C struct representation of `std::error_code`.

  - ## Namespace `outcome_v2_xxx::convert`
    
    <span id="standardese-outcome_v2_xxx__convert"></span>

    Namespace for injected convertibility
    
      - [`ValueOrError`](convert#standardese-outcome_v2_xxx__convert)
    
      - [`ValueOrNone`](convert#standardese-outcome_v2_xxx__convert)
    
      - [`value_or_error`](convert#standardese-outcome_v2_xxx__convert__value_or_error-T-U-) &mdash; Default converter for types matching the `ValueOrError` concept.

  - ## Namespace `outcome_v2_xxx::hooks`
    
    <span id="standardese-outcome_v2_xxx__hooks"></span>

    Namespace containing hooks used for intercepting and manipulating result/outcome
    
      - [`hook_outcome_construction`](outcome#standardese-outcome_v2_xxx__hooks__hook_outcome_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `outcome` is first created by conversion from one of its possible types. Does nothing.
    
      - [`hook_outcome_copy_construction`](outcome#standardese-outcome_v2_xxx__hooks__hook_outcome_copy_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `outcome` is created by copying from another `outcome` or `result`. Does nothing.
    
      - [`hook_outcome_in_place_construction`](outcome#standardese-outcome_v2_xxx__hooks__hook_outcome_in_place_construction-T-U-Args--T--in_place_type_t-U--Args------) &mdash; The default instantiation hook implementation called when a `outcome` is created by in place construction. Does nothing.
    
      - [`hook_outcome_move_construction`](outcome#standardese-outcome_v2_xxx__hooks__hook_outcome_move_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `outcome` is created by moving from another `outcome` or `result`. Does nothing.
    
      - [`hook_result_construction`](result#standardese-outcome_v2_xxx__hooks__hook_result_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `result` is first created by conversion from one of its possible types. Does nothing.
    
      - [`hook_result_copy_construction`](result#standardese-outcome_v2_xxx__hooks__hook_result_copy_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `result` is created by copying from another `result`. Does nothing.
    
      - [`hook_result_in_place_construction`](result#standardese-outcome_v2_xxx__hooks__hook_result_in_place_construction-T-U-Args--T--in_place_type_t-U--Args------) &mdash; The default instantiation hook implementation called when a `result` is created by in place construction. Does nothing.
    
      - [`hook_result_move_construction`](result#standardese-outcome_v2_xxx__hooks__hook_result_move_construction-T-U--T--U---) &mdash; The default instantiation hook implementation called when a `result` is created by moving from another `result`. Does nothing.
    
      - [`override_outcome_exception`](outcome#standardese-outcome_v2_xxx__hooks__override_outcome_exception-R-S-P-NoValuePolicy-U--outcome-R-S-P-NoValuePolicy---U---) &mdash; Used in hook implementations to override the payload/exception to something other than what was constructed.
    
      - [`set_spare_storage`](result#standardese-outcome_v2_xxx__hooks__set_spare_storage-R-S-NoValuePolicy--detail__result_final-R-S-NoValuePolicy---uint16_t-) &mdash; Sets the sixteen bits of spare storage in a `result` or `outcome`.
    
      - [`spare_storage`](result#standardese-outcome_v2_xxx__hooks__spare_storage-R-S-NoValuePolicy--detail__result_final-R-S-NoValuePolicy-const--) &mdash; Get the sixteen bits of spare storage in a `result` or `outcome`.

  - ## Namespace `outcome_v2_xxx::policy`
    
    <span id="standardese-outcome_v2_xxx__policy"></span>

    Namespace for policies
    
      - [`all_narrow`](policies/all_narrow#standardese-outcome_v2_xxx__policy__all_narrow) &mdash; Policy which treats wide checks as narrow checks.
    
      - [`default_policy`](result#standardese-outcome_v2_xxx__policy__default_policy-T-EC-E-) &mdash; Default policy selector.
    
      - [`error_code`](success_failure#standardese-outcome_v2_xxx__policy__error_code-T--T---) &mdash; Used by policies to extract a `std::error_code` from some input `T` via ADL discovery of some `make_error_code(T)` function.
    
      - [`error_code_throw_as_system_error`](policies/result_error_code_throw_as_system_error#standardese-outcome_v2_xxx__policy__error_code_throw_as_system_error-T-EC-) &mdash; Policy interpreting `EC` as a type for which `trait::has_error_code_v<EC>` is true.
    
      - [`exception_ptr`](success_failure#standardese-outcome_v2_xxx__policy__exception_ptr-T--T---) &mdash; Used by policies to extract a `std::exception_ptr` from some input `T` via ADL discovery of some `make_exception_ptr(T)` function.
    
      - [`exception_ptr_rethrow`](policies/outcome_exception_ptr_rethrow#standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-) &mdash; Policy interpreting `EC` or `E` as a type for which `trait::has_exception_ptr_v<EC|E>` is true.
    
      - [`terminate`](policies/terminate#standardese-outcome_v2_xxx__policy__terminate) &mdash; Policy implementing any wide attempt to access the successful state as calling `std::terminate`
    
      - [`throw_as_system_error_with_payload`](success_failure#standardese-outcome_v2_xxx__policy__throw_as_system_error_with_payload-Error--Errorconst--) &mdash; Override to define what the policies which throw a system error with payload ought to do for some particular `result.error()`.
    
      - [`throw_bad_result_access`](policies/throw_bad_result_access#standardese-outcome_v2_xxx__policy__throw_bad_result_access-EC-) &mdash; Policy which throws `bad_result_access_with<EC>` or `bad_result_access` during wide checks.

  - ## Namespace `outcome_v2_xxx::trait`
    
    <span id="standardese-outcome_v2_xxx__trait"></span>

    Namespace for traits
    
      - [`has_error_code`](success_failure#standardese-outcome_v2_xxx__trait__has_error_code-T-) &mdash; Trait for whether a free function `make_error_code(T)` returning a `std::error_code` exists or not.
    
      - [`has_error_code_v`](success_failure#standardese-outcome_v2_xxx__trait__has_error_code_v) &mdash; Trait for whether a free function `make_error_code(T)` returning a `std::error_code` exists or not.
    
      - [`has_exception_ptr`](success_failure#standardese-outcome_v2_xxx__trait__has_exception_ptr-T-) &mdash; Trait for whether a free function `make_exception_ptr(T)` returning a `std::exception_ptr` exists or not.
    
      - [`has_exception_ptr_v`](success_failure#standardese-outcome_v2_xxx__trait__has_exception_ptr_v) &mdash; Trait for whether a free function `make_exception_ptr(T)` returning a `std::exception_ptr` exists or not.

  - ## Namespace `outcome_v2_xxx`
    
    <span id="standardese-outcome_v2_xxx"></span>

      - [`bad_outcome_access`](bad_access#standardese-outcome_v2_xxx__bad_outcome_access) &mdash; Thrown when you try to access state in a `outcome<T, EC, E>` which isn’t present.
    
      - [`bad_result_access`](bad_access#standardese-outcome_v2_xxx__bad_result_access) &mdash; Thrown when you try to access state in a `result<R, S>` which isn’t present.
    
      - [`bad_result_access_with`](bad_access#standardese-outcome_v2_xxx__bad_result_access_with-S-) &mdash; Thrown when you try to access a value in a `result<R, S>` which isn’t present.
    
      - [`checked`](result#standardese-outcome_v2_xxx__checked-R-S-) &mdash; A “checked” edition of `result<T, E>` which resembles fairly closely a `std::expected<T, E>`.
    
      - [`error_from_exception`](utils#standardese-outcome_v2_xxx__error_from_exception-std__exception_ptr---std__error_code-) &mdash; Utility function which tries to match the exception in the pointer provided to an equivalent error code. Ought to work for all standard STL types.
    
      - [`failure`](success_failure#standardese-outcome_v2_xxx__failure-EC--EC---) &mdash; Returns type sugar for implicitly constructing a `result<T>` with a failure state.
    
      - [`failure_type`](success_failure#standardese-outcome_v2_xxx__failure_type-EC-E-) &mdash; Type sugar for implicitly constructing a `result<>` with a failure state of error code and exception.
    
      - `in_place_type` &mdash; Aliases `std::in_place_type<T>` if on C++ 17 or later, else defined locally.
    
      - `in_place_type_t` &mdash; Aliases `std::in_place_type_t<T>` if on C++ 17 or later, else defined locally.
    
      - [`is_outcome`](outcome#standardese-outcome_v2_xxx__is_outcome-T-) &mdash; True if an outcome
    
      - [`is_outcome_v`](outcome#standardese-outcome_v2_xxx__is_outcome_v) &mdash; True if an outcome
    
      - [`is_result`](result#standardese-outcome_v2_xxx__is_result-T-) &mdash; True if a result
    
      - [`is_result_v`](result#standardese-outcome_v2_xxx__is_result_v) &mdash; True if a result
    
      - [`operator!=`](outcome#standardese-outcome_v2_xxx__operator---T-U-V-R-S-P-N---result-T-U-V-const--outcome-R-S-P-N-const--) &mdash; True if the result is not equal to the outcome
    
      - [`operator<<`](iostream_support#standardese-outcome_v2_xxx__operator---R-S-P----std__ostream--result-R-S-P-const--) &mdash; Serialise a result. Format is `status_unsigned [value][error]`. Spare storage is preserved.
    
      - [`operator==`](outcome#standardese-outcome_v2_xxx__operator---T-U-V-R-S-P-N---result-T-U-V-const--outcome-R-S-P-N-const--) &mdash; True if the result is equal to the outcome
    
      - [`operator>>`](iostream_support#standardese-outcome_v2_xxx__operator---R-S-P----std__istream--result-R-S-P---) &mdash; Deserialise a result. Format is `status_unsigned [value][error]`. Spare storage is preserved.
    
      - [`outcome`](outcome#standardese-outcome_v2_xxx__outcome-R-S-P-NoValuePolicy-) &mdash; Used to return from functions one of (i) a successful value (ii) a cause of failure (ii) a different cause of failure. `constexpr` capable.
    
      - [`print`](iostream_support#standardese-outcome_v2_xxx__print-R-S-P--detail__result_final-R-S-P-const--) &mdash; Debug print a result into a form suitable for human reading. Format is `value|error`. If the error type is `error_code`, appends `" (ec.message())"` afterwards.
    
      - [`result`](result#standardese-outcome_v2_xxx__result-R-S-NoValuePolicy-) &mdash; Used to return from functions either (i) a successful value (ii) a cause of failure. `constexpr` capable.
    
      - [`success`](success_failure#standardese-outcome_v2_xxx__success-T--T---) &mdash; Returns type sugar for implicitly constructing a `result<T>` with a successful state, default constructing `T` if necessary.
    
      - [`success_type`](success_failure#standardese-outcome_v2_xxx__success_type-T-) &mdash; Type sugar for implicitly constructing a `result<>` with a successful state.
    
      - [`swap`](result#standardese-outcome_v2_xxx__swap-R-S-P--result-R-S-P---result-R-S-P---) &mdash; Specialise swap for result.
    
      - [`try_operation_return_as`](try#standardese-outcome_v2_xxx__try_operation_return_as-T--T---) &mdash; Customisation point for changing what the `OUTCOME_TRY` macros do. This function defaults to returning `std::forward<T>(v).as_failure()`.
    
      - [`try_throw_std_exception_from_error`](utils#standardese-outcome_v2_xxx__try_throw_std_exception_from_error-std__error_code-std__stringconst--) &mdash; Utility function which tries to throw the equivalent STL exception type for some given error code, not including `system_error`.
    
      - [`unchecked`](result#standardese-outcome_v2_xxx__unchecked-R-S-) &mdash; An “unchecked” edition of `result<T, E>` which does no special handling of specific `E` types at all.
