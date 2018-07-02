/* A very simple result type
(C) 2017 Niall Douglas <http://www.nedproductions.biz/> (59 commits)
File Created: June 2017


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License in the accompanying file
Licence.txt or at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Distributed under the Boost Software License, Version 1.0.
(See accompanying file Licence.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OUTCOME_RESULT_HPP
#define OUTCOME_RESULT_HPP

#include "convert.hpp"
#include "detail/result_final.hpp"

#include "policy/all_narrow.hpp"
#include "policy/result_error_code_throw_as_system_error.hpp"
#include "policy/result_exception_ptr_rethrow.hpp"
#include "policy/terminate.hpp"
#include "policy/throw_bad_result_access.hpp"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"  // Standardese markup confuses clang
#endif

OUTCOME_V2_NAMESPACE_EXPORT_BEGIN

//! Namespace for policies
namespace policy
{
  /*! Default policy selector.
  */
  template <class T, class EC, class E>
  using default_policy = std::conditional_t<  //
  std::is_void<EC>::value && std::is_void<E>::value,
  terminate,                                                                                         //
  std::conditional_t<                                                                                //
  trait::has_error_code_v<EC>, error_code_throw_as_system_error<T, EC, E>,                           //
  std::conditional_t<                                                                                //
  trait::has_exception_ptr_v<EC> || trait::has_exception_ptr_v<E>, exception_ptr_rethrow<T, EC, E>,  //
  all_narrow                                                                                         //
  >>>;
}  // namespace policy

template <class R, class S = std::error_code, class NoValuePolicy = policy::default_policy<R, S, void>>                                                                 //
#if !defined(__GNUC__) || __GNUC__ >= 8                                                                                                                                 // GCC's constraints implementation is buggy
OUTCOME_REQUIRES(detail::type_can_be_used_in_result<R> &&detail::type_can_be_used_in_result<S> && (std::is_void<S>::value || std::is_default_constructible<S>::value))  //
#endif
class result;

namespace detail
{
  // These are reused by outcome to save load on the compiler
  template <class value_type, class error_type> struct result_predicates
  {
    // Is this a common error type?
    static constexpr bool error_is_common_error_type =  //
    trait::has_error_code_v<error_type> || trait::has_exception_ptr_v<error_type>;

    // Predicate for the implicit constructors to be available
    static constexpr bool implicit_constructors_enabled =                                                                                                  //
    ((error_is_common_error_type && std::is_same<bool, std::decay_t<value_type>>::value) || !detail::is_implicitly_constructible<value_type, error_type>)  //
    &&!detail::is_implicitly_constructible<error_type, value_type>;

    // Predicate for the value converting constructor to be available.
    template <class T>
    static constexpr bool enable_value_converting_constructor =  //
    implicit_constructors_enabled                                //
    && !is_in_place_type_t<std::decay_t<T>>::value               // not in place construction
    && detail::is_implicitly_constructible<value_type, T> && !detail::is_implicitly_constructible<error_type, T>;

    // Predicate for the error converting constructor to be available.
    template <class T>
    static constexpr bool enable_error_converting_constructor =  //
    implicit_constructors_enabled                                //
    && !is_in_place_type_t<std::decay_t<T>>::value               // not in place construction
    && !detail::is_implicitly_constructible<value_type, T> && detail::is_implicitly_constructible<error_type, T>;

    // Predicate for the error condition converting constructor to be available.
    template <class ErrorCondEnum>
    static constexpr bool enable_error_condition_converting_constructor =                                                                   //
    !is_in_place_type_t<std::decay_t<ErrorCondEnum>>::value                                                                                 // not in place construction
    && std::is_error_condition_enum<ErrorCondEnum>::value                                                                                   // is an error condition enum
    && !detail::is_implicitly_constructible<value_type, ErrorCondEnum> && !detail::is_implicitly_constructible<error_type, ErrorCondEnum>;  // not constructible via any other means

    // Predicate for the converting copy constructor from a compatible input to be available.
    template <class T, class U, class V>
    static constexpr bool enable_compatible_conversion =                                                                 //
    (std::is_void<T>::value || detail::is_explicitly_constructible<value_type, typename result<T, U, V>::value_type>)    // if our value types are constructible
    &&(std::is_void<U>::value || detail::is_explicitly_constructible<error_type, typename result<T, U, V>::error_type>)  // if our error types are constructible
    ;

    // Predicate for the implicit converting inplace constructor from a compatible input to be available.
    struct disable_inplace_value_error_constructor;
    template <class... Args>
    using choose_inplace_value_error_constructor = std::conditional_t<                                       //
    std::is_constructible<value_type, Args...>::value && std::is_constructible<error_type, Args...>::value,  //
    disable_inplace_value_error_constructor,                                                                 //
    std::conditional_t<                                                                                      //
    std::is_constructible<value_type, Args...>::value,                                                       //
    value_type,                                                                                              //
    std::conditional_t<                                                                                      //
    std::is_constructible<error_type, Args...>::value,                                                       //
    error_type,                                                                                              //
    disable_inplace_value_error_constructor>>>;
    template <class... Args>
    static constexpr bool enable_inplace_value_error_constructor = implicit_constructors_enabled  //
                                                                   && !std::is_same<choose_inplace_value_error_constructor<Args...>, disable_inplace_value_error_constructor>::value;
  };

  template <class T, class U> constexpr inline const U &extract_value_from_success(const success_type<U> &v) { return v.value(); }
  template <class T, class U> constexpr inline U &&extract_value_from_success(success_type<U> &&v) { return std::move(v).value(); }
  template <class T> constexpr inline T extract_value_from_success(const success_type<void> & /*unused*/) { return T{}; }

  template <class T, class U, class V> constexpr inline const U &extract_error_from_failure(const failure_type<U, V> &v) { return v.error(); }
  template <class T, class U, class V> constexpr inline U &&extract_error_from_failure(failure_type<U, V> &&v) { return std::move(v).error(); }
  template <class T, class V> constexpr inline T extract_error_from_failure(const failure_type<void, V> & /*unused*/) { return T{}; }

  template <class T> struct is_result : std::false_type
  {
  };
  template <class R, class S, class T> struct is_result<result<R, S, T>> : std::true_type
  {
  };
}  // namespace detail

//! True if a result
template <class T> using is_result = detail::is_result<std::decay_t<T>>;
//! True if a result
template <class T> static constexpr bool is_result_v = detail::is_result<std::decay_t<T>>::value;

//! Namespace for ADL discovered hooks into events in `result` and `outcome`.
namespace hooks
{
  /*! The default instantiation hook implementation called when a `result` is first created
  by conversion from one of its possible types. Does nothing.
  \param 1 Some `result<...>` being constructed.
  \param 2 The source data.

  WARNING: The compiler is permitted to elide calls to constructors, and thus this hook may not get called when you think it should!
  */
  template <class T, class U> constexpr inline void hook_result_construction(T * /*unused*/, U && /*unused*/) noexcept {}
  /*! The default instantiation hook implementation called when a `result` is created by copying
  from another `result`. Does nothing.
  \param 1 Some `result<...>` being constructed.
  \param 2 The source data.

  WARNING: The compiler is permitted to elide calls to constructors, and thus this hook may not get called when you think it should!
  */
  template <class T, class U> constexpr inline void hook_result_copy_construction(T * /*unused*/, U && /*unused*/) noexcept {}
  /*! The default instantiation hook implementation called when a `result` is created by moving
  from another `result`. Does nothing.
  \param 1 Some `result<...>` being constructed.
  \param 2 The source data.

  WARNING: The compiler is permitted to elide calls to constructors, and thus this hook may not get called when you think it should!
  */
  template <class T, class U> constexpr inline void hook_result_move_construction(T * /*unused*/, U && /*unused*/) noexcept {}
  /*! The default instantiation hook implementation called when a `result` is created by in place
  construction. Does nothing.
  \param 1 Some `result<...>` being constructed.
  \param 2 The type of in place construction occurring.
  \param 3 The source data.

  WARNING: The compiler is permitted to elide calls to constructors, and thus this hook may not get called when you think it should!
  */
  template <class T, class U, class... Args> constexpr inline void hook_result_in_place_construction(T * /*unused*/, in_place_type_t<U> /*unused*/, Args &&... /*unused*/) noexcept {}

  //! Retrieves the 16 bits of spare storage in result/outcome.
  template <class R, class S, class NoValuePolicy> constexpr inline uint16_t spare_storage(const detail::result_final<R, S, NoValuePolicy> *r) noexcept { return (r->_state._status >> detail::status_2byte_shift) & 0xffff; }
  //! Sets the 16 bits of spare storage in result/outcome.
  template <class R, class S, class NoValuePolicy> constexpr inline void set_spare_storage(detail::result_final<R, S, NoValuePolicy> *r, uint16_t v) noexcept { r->_state._status |= (v << detail::status_2byte_shift); }
}  // namespace hooks

/*! Used to return from functions either (i) a successful value (ii) a cause of failure. `constexpr` capable.

\tparam R The optional type of the successful result (use `void` to disable). Cannot be a reference, a `in_place_type_t<>`, `success<>`, `failure<>`, an array, a function or non-destructible.
\tparam S The optional type of the failure result (use `void` to disable). Must be either `void` or `DefaultConstructible`. Cannot be a reference, a `in_place_type_t<>`, `success<>`, `failure<>`, an array, a function or non-destructible.
\tparam NoValuePolicy Policy on how to interpret type `S` when a wide observation of a not present value occurs.

Any `R` (`value_type`) state can be observed using the member functions `.value()` and `.assume_value()`. Any `S` (`error_type`) state can be
observed using the member functions `.error()` and `.assume_error()`.

`NoValuePolicy` defaults to a policy selected according to the characteristics of type `S`:

1. If `.value()` called when there is no `value_type` but there is an `error_type`:
   - If \verbatim {{<api "success_failure/#unexposed-entity-outcome-v2-xxx-trait-has-error-code-v" "trait::has_error_code_v<S>">}} \end is true,
then `throw std::system_error(error()|make_error_code(error()))` [\verbatim {{<api "policies/result_error_code_throw_as_system_error" "policy::error_code_throw_as_system_error<S>">}} \end]
   - If \verbatim {{<api "success_failure/#unexposed-entity-outcome-v2-xxx-trait-has-exception-ptr-v" "trait::has_exception_ptr_v<S>">}} \end is true, then `std::rethrow_exception(error()|make_exception_ptr(error()))`
[\verbatim {{<api "policies/result_exception_ptr_rethrow/" "policy::exception_ptr_rethrow<R, S, void>">}} \end]
   - If `S` is `void`, call `std::terminate()` [\verbatim {{<api "policies/terminate/" "policy::terminate">}} \end]
   - If `S` is none of the above, then it is undefined behaviour [\verbatim {{<api "policies/all_narrow/" "policy::all_narrow">}} \end]
2. If `.error()` called when there is no `error_type`:
   - If `trait::has_error_code_v<S>`, or if `trait::has_exception_ptr_v<S>`,
or if `S` is `void`, do `throw bad_result_access()`
   - If `S` is none of the above, then it is undefined behaviour [`policy::all_narrow`]
*/
template <class R, class S, class NoValuePolicy>                                                                                                                        //
#if !defined(__GNUC__) || __GNUC__ >= 8                                                                                                                                 // GCC's constraints implementation is buggy
OUTCOME_REQUIRES(detail::type_can_be_used_in_result<R> &&detail::type_can_be_used_in_result<S> && (std::is_void<S>::value || std::is_default_constructible<S>::value))  //
#endif
class OUTCOME_NODISCARD result : public detail::result_final<R, S, NoValuePolicy>
{
  static_assert(detail::type_can_be_used_in_result<R>, "The type R cannot be used in a result");
  static_assert(detail::type_can_be_used_in_result<S>, "The type S cannot be used in a result");
  static_assert(std::is_void<S>::value || std::is_default_constructible<S>::value, "The type S must be void or default constructible");

  using base = detail::result_final<R, S, NoValuePolicy>;

  struct value_converting_constructor_tag
  {
  };
  struct error_converting_constructor_tag
  {
  };
  struct error_condition_converting_constructor_tag
  {
  };
  struct explicit_valueornone_converting_constructor_tag
  {
  };
  struct explicit_valueorerror_converting_constructor_tag
  {
  };

public:
  /// \output_section Member types
  //! The success type.
  using value_type = R;
  //! The failure type.
  using error_type = S;

  //! Used to disable in place type construction when `value_type` and `error_type` are ambiguous.
  using value_type_if_enabled = typename base::_value_type;
  //! Used to disable in place type construction when `value_type` and `error_type` are ambiguous.
  using error_type_if_enabled = typename base::_error_type;

  //! Used to rebind this result to a different result type.
  template <class T, class U = S, class V = policy::default_policy<T, U, void>> using rebind = result<T, U, V>;

protected:
  //! Requirement predicates for result.
  struct predicate
  {
    using base = detail::result_predicates<value_type, error_type>;

    //! Predicate for the value converting constructor to be available.
    template <class T>
    static constexpr bool enable_value_converting_constructor =  //
    !std::is_same<std::decay_t<T>, result>::value                // not my type
    && base::template enable_value_converting_constructor<T>;

    //! Predicate for the error converting constructor to be available.
    template <class T>
    static constexpr bool enable_error_converting_constructor =  //
    !std::is_same<std::decay_t<T>, result>::value                // not my type
    && base::template enable_error_converting_constructor<T>;

    //! Predicate for the error condition converting constructor to be available.
    template <class ErrorCondEnum>
    static constexpr bool enable_error_condition_converting_constructor =  //
    !std::is_same<std::decay_t<ErrorCondEnum>, result>::value              // not my type
    && base::template enable_error_condition_converting_constructor<ErrorCondEnum>;

    //! Predicate for the converting copy constructor from a compatible input to be available.
    template <class T, class U, class V>
    static constexpr bool enable_compatible_conversion =  //
    !std::is_same<result<T, U, V>, result>::value         // not my type
    && base::template enable_compatible_conversion<T, U, V>;

    //! Predicate for the inplace construction of value to be available.
    template <class... Args>
    static constexpr bool enable_inplace_value_constructor =  //
    std::is_void<value_type>::value                           //
    || std::is_constructible<value_type, Args...>::value;

    //! Predicate for the inplace construction of error to be available.
    template <class... Args>
    static constexpr bool enable_inplace_error_constructor =  //
    std::is_void<error_type>::value                           //
    || std::is_constructible<error_type, Args...>::value;

    // Predicate for the implicit converting inplace constructor to be available.
    template <class... Args>
    static constexpr bool enable_inplace_value_error_constructor =  //
    base::template enable_inplace_value_error_constructor<Args...>;
    template <class... Args> using choose_inplace_value_error_constructor = typename base::template choose_inplace_value_error_constructor<Args...>;
  };

public:
  /// \output_section Default, copy/move constructors and assignment
  //! Default construction is not permitted.
  result() = delete;
  //! Move construction available if `value_type` and `error_type` implement it.
  result(result && /*unused*/) = default;  // NOLINT
  //! Copy construction available if `value_type` and `error_type` implement it.
  result(const result & /*unused*/) = default;
  //! Move assignment available if `value_type` and `error_type` implement it.
  result &operator=(result && /*unused*/) = default;  // NOLINT
  //! Copy assignment available if `value_type` and `error_type` implement it.
  result &operator=(const result & /*unused*/) = default;
  ~result() = default;

  /// \output_section Converting constructors
  /*! Implicit converting constructor to a successful result.
  \tparam 1
  \exclude
  \param 1
  \exclude
  \param t The value from which to initialise the `value_type`.

  \effects Initialises the result with a `value_type`.
  \requires Type T is implicitly constructible to `value_type`, is not implicitly constructible to `error_type`, and is not `result<R, S>` and not `in_place_type<>`.
  \throws Any exception the construction of `value_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_value_converting_constructor<T>))
  constexpr result(T &&t, value_converting_constructor_tag /*unused*/ = value_converting_constructor_tag()) noexcept(std::is_nothrow_constructible<value_type, T>::value)  // NOLINT
  : base{in_place_type<typename base::value_type>, std::forward<T>(t)}
  {
    using namespace hooks;
    hook_result_construction(this, std::forward<T>(t));
  }
  /*! Implicit converting constructor to a failure result.
  \tparam 1
  \exclude
  \param 1
  \exclude
  \param t The value from which to initialise the `error_type`.

  \effects Initialises the result with a `error_type`.
  \requires Type T is implicitly constructible to `error_type`,
  is not implicitly constructible to `value_type`, and is not `result<R, S>` and not `in_place_type<>`.
  \throws Any exception the construction of `error_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_error_converting_constructor<T>))
  constexpr result(T &&t, error_converting_constructor_tag /*unused*/ = error_converting_constructor_tag()) noexcept(std::is_nothrow_constructible<error_type, T>::value)  // NOLINT
  : base{in_place_type<typename base::error_type>, std::forward<T>(t)}
  {
    using namespace hooks;
    hook_result_construction(this, std::forward<T>(t));
  }
  /*! Implicit special error condition converting constructor to a failure result.
  \tparam 1
  \exclude
  \tparam 2
  \exclude
  \param 1
  \exclude
  \param t The error condition from which to initialise the `error_type`.

  \effects Initialises the result with a `error_type` constructed via `make_error_code(t)`.
  \requires `std::is_error_condition_enum<ErrorCondEnum>` must be true,
  `ErrorCondEnum` is not implicitly constructible to `value_type` nor `error_type`, and is not `result<R, S>` and not `in_place_type<>`;
  Finally, the expression `error_type(make_error_code(ErrorCondEnum()))` must be valid.
  \throws Any exception the construction of `error_type(make_error_code(t))` might throw.
  */
  OUTCOME_TEMPLATE(class ErrorCondEnum)
  OUTCOME_TREQUIRES(OUTCOME_TEXPR(error_type(make_error_code(ErrorCondEnum()))),  //
                    OUTCOME_TPRED(predicate::template enable_error_condition_converting_constructor<ErrorCondEnum>))
  constexpr result(ErrorCondEnum &&t, error_condition_converting_constructor_tag /*unused*/ = error_condition_converting_constructor_tag()) noexcept(noexcept(error_type(make_error_code(std::forward<ErrorCondEnum>(t)))))  // NOLINT
  : base{in_place_type<typename base::error_type>, make_error_code(t)}
  {
    using namespace hooks;
    hook_result_construction(this, std::forward<ErrorCondEnum>(t));
  }

  /*! Explicit converting constructor from a compatible `ValueOrError` type.
  \tparam 1
  \exclude
  \tparam 2
  \exclude
  \param 1
  \exclude
  \param o The input for which a `convert::value_or_error<result, std::decay_t<T>>{}(std::forward<T>(o))` is available.

  \effects Initialises the result with the contents of the compatible input.
  \requires That `convert::value_or_error<result, std::decay_t<T>>{}(std::forward<T>(o))` be available. The
  default implementation will consume `T`'s matching the `ValueOrError` concept type.
  `ValueOrError` concept matches any type with a `value_type`,
  an `error_type`, a `.value()`, an `.error()` and a `.has_value()`.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(convert::value_or_error<result, std::decay_t<T>>::enable_result_inputs || !is_result_v<T>),  //
                    OUTCOME_TEXPR(convert::value_or_error<result, std::decay_t<T>>{}(std::declval<T>())))
  constexpr explicit result(T &&o, explicit_valueorerror_converting_constructor_tag /*unused*/ = explicit_valueorerror_converting_constructor_tag())  // NOLINT
  : result{convert::value_or_error<result, std::decay_t<T>>{}(std::forward<T>(o))}
  {
  }
  /*! Explicit converting copy constructor from a compatible result type.
  \tparam 3
  \exclude
  \param o The compatible result.

  \effects Initialises the result with a copy of the compatible result.
  \requires Both result's `value_type` and `error_type` need to be constructible, or the source can be `void`.
  \throws Any exception the construction of `value_type(T)` and `error_type(U)` might throw.
  */
  OUTCOME_TEMPLATE(class T, class U, class V)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_compatible_conversion<T, U, V>))
  constexpr explicit result(const result<T, U, V> &o) noexcept(std::is_nothrow_constructible<value_type, T>::value &&std::is_nothrow_constructible<error_type, U>::value)
      : base{typename base::compatible_conversion_tag(), o}
  {
    using namespace hooks;
    hook_result_copy_construction(this, o);
  }
  /*! Explicit converting move constructor from a compatible result type.
  \tparam 3
  \exclude
  \param o The compatible result.

  \effects Initialises the result with a move of the compatible result.
  \requires Both result's `value_type` and `error_type` need to be constructible, or the source can be `void`.
  \throws Any exception the construction of `value_type(T)` and `error_type(U)` might throw.
  */
  OUTCOME_TEMPLATE(class T, class U, class V)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_compatible_conversion<T, U, V>))
  constexpr explicit result(result<T, U, V> &&o) noexcept(std::is_nothrow_constructible<value_type, T>::value &&std::is_nothrow_constructible<error_type, U>::value)
      : base{typename base::compatible_conversion_tag(), std::move(o)}
  {
    using namespace hooks;
    hook_result_move_construction(this, std::move(o));
  }

  /// \output_section In place constructors
  /*! Explicit inplace constructor to a successful result.
  \tparam 1
  \exclude
  \param _ Tag type to indicate we are doing in place construction of `value_type`.
  \param args Arguments with which to in place construct.

  \effects Initialises the result with a `value_type`.
  \requires `value_type` is void or `Args...` are constructible to `value_type`.
  \throws Any exception the construction of `value_type(Args...)` might throw.
  */
  OUTCOME_TEMPLATE(class... Args)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_inplace_value_constructor<Args...>))
  constexpr explicit result(in_place_type_t<value_type_if_enabled> _, Args &&... args) noexcept(std::is_nothrow_constructible<value_type, Args...>::value)
      : base{_, std::forward<Args>(args)...}
  {
    using namespace hooks;
    hook_result_in_place_construction(this, in_place_type<value_type>, std::forward<Args>(args)...);
  }
  /*! Explicit inplace constructor to a successful result.
  \tparam 2
  \exclude
  \param _ Tag type to indicate we are doing in place construction of `value_type`.
  \param il An initializer list with which to in place construct.
  \param args Arguments with which to in place construct.

  \effects Initialises the result with a `value_type`.
  \requires The initializer list + `Args...` are constructible to `value_type`.
  \throws Any exception the construction of `value_type(il, Args...)` might throw.
  */
  OUTCOME_TEMPLATE(class U, class... Args)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_inplace_value_constructor<std::initializer_list<U>, Args...>))
  constexpr explicit result(in_place_type_t<value_type_if_enabled> _, std::initializer_list<U> il, Args &&... args) noexcept(std::is_nothrow_constructible<value_type, std::initializer_list<U>, Args...>::value)
      : base{_, il, std::forward<Args>(args)...}
  {
    using namespace hooks;
    hook_result_in_place_construction(this, in_place_type<value_type>, il, std::forward<Args>(args)...);
  }
  /*! Explicit inplace constructor to a failure result.
  \tparam 1
  \exclude
  \param _ Tag type to indicate we are doing in place construction of `error_type`.
  \param args Arguments with which to in place construct.

  \effects Initialises the result with a `error_type`.
  \requires `error_type` is void or `Args...` are constructible to `error_type`.
  \throws Any exception the construction of `error_type(Args...)` might throw.
  */
  OUTCOME_TEMPLATE(class... Args)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_inplace_error_constructor<Args...>))
  constexpr explicit result(in_place_type_t<error_type_if_enabled> _, Args &&... args) noexcept(std::is_nothrow_constructible<error_type, Args...>::value)
      : base{_, std::forward<Args>(args)...}
  {
    using namespace hooks;
    hook_result_in_place_construction(this, in_place_type<error_type>, std::forward<Args>(args)...);
  }
  /*! Explicit inplace constructor to a failure result.
  \tparam 2
  \exclude
  \param _ Tag type to indicate we are doing in place construction of `error_type`.
  \param il An initializer list with which to in place construct.
  \param args Arguments with which to in place construct.

  \effects Initialises the result with a `error_type`.
  \requires The initializer list + `Args...` are constructible to `error_type`.
  \throws Any exception the construction of `error_type(il, Args...)` might throw.
  */
  OUTCOME_TEMPLATE(class U, class... Args)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_inplace_error_constructor<std::initializer_list<U>, Args...>))
  constexpr explicit result(in_place_type_t<error_type_if_enabled> _, std::initializer_list<U> il, Args &&... args) noexcept(std::is_nothrow_constructible<error_type, std::initializer_list<U>, Args...>::value)
      : base{_, il, std::forward<Args>(args)...}
  {
    using namespace hooks;
    hook_result_in_place_construction(this, in_place_type<error_type>, il, std::forward<Args>(args)...);
  }
  /*! Implicit inplace constructor to successful or failure result.
  \tparam 3
  \exclude
  \param args Arguments with which to in place construct.

  \effects Calls the appropriate `in_place_type_t<...>` constructor depending on constructibility of args.
  \requires That the args can construct exactly one of `value_type` or `error_type`.
  \throws Any exception the `in_place_type_t<...>` constructor might throw.
  */
  OUTCOME_TEMPLATE(class A1, class A2, class... Args)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_inplace_value_error_constructor<A1, A2, Args...>))
  constexpr result(A1 &&a1, A2 &&a2, Args &&... args) noexcept(noexcept(typename predicate::template choose_inplace_value_error_constructor<A1, A2, Args...>(std::declval<A1>(), std::declval<A2>(), std::declval<Args>()...)))
      : result(in_place_type<typename predicate::template choose_inplace_value_error_constructor<A1, A2, Args...>>, std::forward<A1>(a1), std::forward<A2>(a2), std::forward<Args>(args)...)
  {
    /* I was a little surprised that the below is needed given that we forward to another constructor.
    But it turns out that ADL only fires on the first constructor for some reason.
    */
    using namespace hooks;
    // hook_result_in_place_construction(in_place_type<typename predicate::template choose_inplace_value_error_constructor<A1, A2, Args...>>, this);
  }

  /// \output_section Tagged constructors
  /*! Implicit tagged constructor of a successful result.
  \param o The compatible success type sugar.

  \effects Initialises the result with a default constructed success type.
  \requires `value_type` to be default constructible, or `void`.
  \throws Any exception the construction of `value_type()` might throw.
  */
  constexpr result(const success_type<void> &o) noexcept(std::is_nothrow_default_constructible<value_type>::value)  // NOLINT
  : base{in_place_type<value_type_if_enabled>}
  {
    using namespace hooks;
    hook_result_copy_construction(this, o);
  }
  /*! Implicit tagged constructor of a successful result.
  \tparam 1
  \exclude
  \param o The compatible success type sugar.

  \effects Initialises the result with a copy of the value in the type sugar.
  \requires Both result and success' `value_type` need to be constructible, or the source can be `void`.
  \throws Any exception the construction of `value_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_compatible_conversion<T, void, void>))
  constexpr result(const success_type<T> &o) noexcept(std::is_nothrow_constructible<value_type, T>::value)  // NOLINT
  : base{in_place_type<value_type_if_enabled>, detail::extract_value_from_success<value_type>(o)}
  {
    using namespace hooks;
    hook_result_copy_construction(this, o);
  }
  /*! Implicit tagged constructor of a successful result.
  \tparam 1
  \exclude
  \param o The compatible success type sugar.

  \effects Initialises the result with a move of the value in the type sugar.
  \requires Both result and success' `value_type` need to be constructible. The source cannot be `void`.
  \throws Any exception the construction of `value_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(!std::is_void<T>::value && predicate::template enable_compatible_conversion<T, void, void>))
  constexpr result(success_type<T> &&o) noexcept(std::is_nothrow_constructible<value_type, T>::value)  // NOLINT
  : base{in_place_type<value_type_if_enabled>, std::move(detail::extract_value_from_success<value_type>(std::move(o)))}
  {
    using namespace hooks;
    hook_result_move_construction(this, std::move(o));
  }
  /*! Implicit tagged constructor of a failure result.
  \tparam 1
  \exclude
  \param o The compatible failure type sugar.

  \effects Initialises the result with a copy of the error in the type sugar.
  \requires Both result and failure's `error_type` need to be constructible, or the source can be `void`.
  \throws Any exception the construction of `error_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_compatible_conversion<void, T, void>))
  constexpr result(const failure_type<T> &o) noexcept(std::is_nothrow_constructible<error_type, T>::value)  // NOLINT
  : base{in_place_type<error_type_if_enabled>, detail::extract_error_from_failure<error_type>(o)}
  {
    using namespace hooks;
    hook_result_copy_construction(this, o);
  }
  /*! Implicit tagged constructor of a failure result.
  \tparam 1
  \exclude
  \param o The compatible failure type sugar.

  \effects Initialises the result with a move of the error in the type sugar.
  \requires Both result and failure's `error_type` need to be constructible, or the source can be `void`.
  \throws Any exception the construction of `error_type(T)` might throw.
  */
  OUTCOME_TEMPLATE(class T)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(predicate::template enable_compatible_conversion<void, T, void>))
  constexpr result(failure_type<T> &&o) noexcept(std::is_nothrow_constructible<error_type, T>::value)  // NOLINT
  : base{in_place_type<error_type_if_enabled>, std::move(detail::extract_error_from_failure<error_type>(std::move(o)))}
  {
    using namespace hooks;
    hook_result_move_construction(this, std::move(o));
  }

  /// \output_section Swap
  /*! Swaps this result with another result
  \effects Any `R` and/or `S` is swapped along with the metadata tracking them.
  */
  void swap(result &o) noexcept(detail::is_nothrow_swappable<value_type>::value  //
                                &&detail::is_nothrow_swappable<error_type>::value)
  {
    using std::swap;
#ifdef __cpp_exceptions
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4297)  // use of throw in noexcept function
#endif
    this->_state.swap(o._state);
    try
    {
      swap(this->_error, o._error);
    }
    catch(...)
    {
      swap(this->_state, o._state);
      throw;
    }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#else
    swap(this->_state, o._state);
    swap(this->_error, o._error);
#endif
  }

  /// \output_section Converters
  /*! Returns this result as a `failure_type` with any errored state copied.
  \requires This result to have a failed state, else whatever `assume_error()` would do.
  */
  auto as_failure() const & { return failure(this->assume_error()); }
  /*! Returns this result as a `failure_type` with any errored state moved.
  \requires This result to have a failed state, else whatever `assume_error()` would do.
  */
  auto as_failure() && { return failure(std::move(this->assume_error())); }
};

/*! Specialise swap for result.
\effects Calls `a.swap(b)`.
*/
template <class R, class S, class P> inline void swap(result<R, S, P> &a, result<R, S, P> &b) noexcept(noexcept(a.swap(b)))
{
  a.swap(b);
}

#if !defined(NDEBUG)
// Check is trivial in all ways except default constructibility
// static_assert(std::is_trivial<result<int>>::value, "result<int> is not trivial!");
// static_assert(std::is_trivially_default_constructible<result<int>>::value, "result<int> is not trivially default constructible!");
static_assert(std::is_trivially_copyable<result<int>>::value, "result<int> is not trivially copyable!");
static_assert(std::is_trivially_assignable<result<int>, result<int>>::value, "result<int> is not trivially assignable!");
static_assert(std::is_trivially_destructible<result<int>>::value, "result<int> is not trivially destructible!");
static_assert(std::is_trivially_copy_constructible<result<int>>::value, "result<int> is not trivially copy constructible!");
static_assert(std::is_trivially_move_constructible<result<int>>::value, "result<int> is not trivially move constructible!");
static_assert(std::is_trivially_copy_assignable<result<int>>::value, "result<int> is not trivially copy assignable!");
static_assert(std::is_trivially_move_assignable<result<int>>::value, "result<int> is not trivially move assignable!");
// Also check is standard layout
static_assert(std::is_standard_layout<result<int>>::value, "result<int> is not a standard layout type!");
#endif

/*! An "unchecked" edition of `result<T, E>` which does no special handling of specific `E` types at all.
Attempting to access `T` when there is an `E` results in nothing happening at all, it is treated with a narrow
contract (i.e. undefined behaviour).
*/
template <class R, class S = std::error_code> using unchecked = result<R, S, policy::all_narrow>;

/*! A "checked" edition of `result<T, E>` which resembles fairly closely a `std::expected<T, E>`.
Attempting to access `T` when there is an `E` results in `bad_result_access<E>` being thrown. Nothing else.

Note that this approximates the proposed `expected<T, E>` up for standardisation, see the FAQ for more
detail.
*/
template <class R, class S = std::error_code> using checked = result<R, S, policy::throw_bad_result_access<S>>;


OUTCOME_V2_NAMESPACE_END

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif
