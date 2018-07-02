/* Try operation macros
(C) 2017 Niall Douglas <http://www.nedproductions.biz/> (59 commits)
File Created: July 2017


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

#ifndef OUTCOME_TRY_HPP
#define OUTCOME_TRY_HPP

#include "success_failure.hpp"

OUTCOME_V2_NAMESPACE_BEGIN

/*! Customisation point for changing what the `OUTCOME_TRY` macros
do. This function defaults to returning `std::forward<T>(v).as_failure()`.
\effects Extracts any state apart from value into a `failure_type`.
\requires The input value to have a `.as_failure()` member function.
*/
template <class T> OUTCOME_REQUIRES(requires(T &&v){{v.as_failure()}}) decltype(auto) try_operation_return_as(T &&v)
{
  return std::forward<T>(v).as_failure();
}

OUTCOME_V2_NAMESPACE_END

//! \exclude
#define OUTCOME_TRY_GLUE2(x, y) x##y
//! \exclude
#define OUTCOME_TRY_GLUE(x, y) OUTCOME_TRY_GLUE2(x, y)
//! \exclude
#define OUTCOME_TRY_UNIQUE_NAME OUTCOME_TRY_GLUE(__t, __COUNTER__)

//! \exclude
#define OUTCOME_TRYV2(unique, ...)                                                                                                                                                                                                                                                                                             \
  auto && (unique) = (__VA_ARGS__);                                                                                                                                                                                                                                                                                            \
  if(!(unique).has_value())                                                                                                                                                                                                                                                                                                    \
  return OUTCOME_V2_NAMESPACE::try_operation_return_as(std::forward<decltype(unique)>(unique))
//! \exclude
#define OUTCOME_TRY2(unique, v, ...)                                                                                                                                                                                                                                                                                           \
  OUTCOME_TRYV2(unique, __VA_ARGS__);                                                                                                                                                                                                                                                                                          \
  auto && (v) = std::forward<decltype(unique)>(unique).value()

/*! If the outcome returned by expression ... is not valued, propagate any
failure by immediately returning that failure state immediately
*/
#define OUTCOME_TRYV(...) OUTCOME_TRYV2(OUTCOME_TRY_UNIQUE_NAME, __VA_ARGS__)

#if defined(__GNUC__) || defined(__clang__)

/*! If the outcome returned by expression ... is not valued, propagate any
failure by immediately returning that failure state immediately, else become the
unwrapped value as an expression. This makes `OUTCOME_TRYX(expr)` an expression
which can be used exactly like the `try` operator in other languages.

\remarks This macro makes use of a proprietary extension in GCC and clang and is not
portable. The macro is not made available on unsupported compilers,
so you can test for its presence using `#ifdef OUTCOME_TRYX`.
*/
#define OUTCOME_TRYX(...)                                                                                                                                                                                                                                                                                                      \
  ({                                                                                                                                                                                                                                                                                                                           \
    auto &&res = (__VA_ARGS__);                                                                                                                                                                                                                                                                                                \
    if(!res.has_value())                                                                                                                                                                                                                                                                                                       \
      return OUTCOME_V2_NAMESPACE::try_operation_return_as(std::forward<decltype(res)>(res));                                                                                                                                                                                                                                  \
    std::forward<decltype(res)>(res).value();                                                                                                                                                                                                                                                                                  \
  \
})
#endif

/*! If the outcome returned by expression ... is not valued, propagate any
failure by immediately returning that failure immediately, else set *v* to the unwrapped value.
*/
#define OUTCOME_TRY(v, ...) OUTCOME_TRY2(OUTCOME_TRY_UNIQUE_NAME, v, __VA_ARGS__)

#endif
