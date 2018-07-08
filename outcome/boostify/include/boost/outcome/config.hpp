/* Configure Boost.Outcome with Boost
(C) 2015-2017 Niall Douglas <http://www.nedproductions.biz/> (24 commits)
File Created: August 2015


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

#ifndef BOOST_OUTCOME_V2_CONFIG_HPP
#define BOOST_OUTCOME_V2_CONFIG_HPP

#include "version.hpp"

// Pull in detection of __MINGW64_VERSION_MAJOR
#if defined(__MINGW32__) && !defined(DOXYGEN_IS_IN_THE_HOUSE)
#include <_mingw.h>
#endif

#include <boost/config.hpp>

#ifdef BOOST_NO_CXX11_VARIADIC_TEMPLATES
#error Boost.Outcome needs variadic template support in the compiler
#endif
#if defined(BOOST_NO_CXX14_CONSTEXPR) && _MSC_FULL_VER < 191100000
#error Boost.Outcome needs constexpr (C++ 14) support in the compiler
#endif
#ifdef BOOST_NO_CXX14_VARIABLE_TEMPLATES
#error Boost.Outcome needs variable template support in the compiler
#endif

#ifndef BOOST_OUTCOME_SYMBOL_VISIBLE
#define BOOST_OUTCOME_SYMBOL_VISIBLE BOOST_SYMBOL_VISIBLE
#endif
// Weird that Boost.Config doesn't define a BOOST_NO_CXX17_NODISCARD
#ifndef BOOST_OUTCOME_NODISCARD
#ifdef __has_cpp_attribute
#if __has_cpp_attribute(nodiscard)
#define BOOST_OUTCOME_NODISCARD [[nodiscard]]
#endif
#elif defined(__clang__)
#define BOOST_OUTCOME_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
// _Must_inspect_result_ expands into this
#define BOOST_OUTCOME_NODISCARD                                                                                                                                                                                                                                                                                                \
  __declspec("SAL_name"                                                                                                                                                                                                                                                                                                        \
             "("                                                                                                                                                                                                                                                                                                               \
             "\"_Must_inspect_result_\""                                                                                                                                                                                                                                                                                       \
             ","                                                                                                                                                                                                                                                                                                               \
             "\"\""                                                                                                                                                                                                                                                                                                            \
             ","                                                                                                                                                                                                                                                                                                               \
             "\"2\""                                                                                                                                                                                                                                                                                                           \
             ")") __declspec("SAL_begin") __declspec("SAL_post") __declspec("SAL_mustInspect") __declspec("SAL_post") __declspec("SAL_checkReturn") __declspec("SAL_end")
#endif
#endif
#ifndef BOOST_OUTCOME_NODISCARD
#define BOOST_OUTCOME_NODISCARD
#endif
#ifndef BOOST_OUTCOME_THREAD_LOCAL
#ifndef BOOST_NO_CXX11_THREAD_LOCAL
#define BOOST_OUTCOME_THREAD_LOCAL thread_local
#else
#if defined(_MSC_VER)
#define BOOST_OUTCOME_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__)
#define BOOST_OUTCOME_THREAD_LOCAL __thread
#else
#error Unknown compiler, cannot set BOOST_OUTCOME_THREAD_LOCAL
#endif
#endif
#endif
// Can't use the QuickCppLib preprocessor metaprogrammed Concepts TS support, so ...
#ifndef BOOST_OUTCOME_TEMPLATE
#define BOOST_OUTCOME_TEMPLATE(...) template <__VA_ARGS__
#endif
#ifndef BOOST_OUTCOME_TREQUIRES
#define BOOST_OUTCOME_TREQUIRES(...) , __VA_ARGS__ >
#endif
#ifndef BOOST_OUTCOME_TEXPR
#define BOOST_OUTCOME_TEXPR(...) typename = decltype(__VA_ARGS__)
#endif
#ifndef BOOST_OUTCOME_TPRED
#define BOOST_OUTCOME_TPRED(...) typename = std::enable_if_t<__VA_ARGS__>
#endif
#ifndef BOOST_OUTCOME_REQUIRES
#ifdef __cpp_concepts
#define BOOST_OUTCOME_REQUIRES(...) requires __VA_ARGS__
#else
#define BOOST_OUTCOME_REQUIRES(...)
#endif
#endif

namespace boost
{
#define BOOST_OUTCOME_V2
  //! The Boost.Outcome namespace
  namespace outcome_v2
  {
  }
}
/*! The namespace of this Boost.Outcome v2.
*/
#define BOOST_OUTCOME_V2_NAMESPACE boost::outcome_v2
/*! Expands into the appropriate namespace markup to enter the Boost.Outcome v2 namespace.
*/
#define BOOST_OUTCOME_V2_NAMESPACE_BEGIN                                                                                                                                                                                                                                                                                       \
  namespace boost                                                                                                                                                                                                                                                                                                              \
  {                                                                                                                                                                                                                                                                                                                            \
    namespace outcome_v2                                                                                                                                                                                                                                                                                                       \
    {
/*! Expands into the appropriate namespace markup to enter the C++ module
exported Boost.Outcome v2 namespace.
*/
#define BOOST_OUTCOME_V2_NAMESPACE_EXPORT_BEGIN                                                                                                                                                                                                                                                                                \
  namespace boost                                                                                                                                                                                                                                                                                                              \
  {                                                                                                                                                                                                                                                                                                                            \
    namespace outcome_v2                                                                                                                                                                                                                                                                                                       \
    {
/*! \brief Expands into the appropriate namespace markup to exit the Boost.Outcome v2 namespace.
\ingroup config
*/
#define BOOST_OUTCOME_V2_NAMESPACE_END                                                                                                                                                                                                                                                                                         \
  }                                                                                                                                                                                                                                                                                                                            \
  }

#include <cstdint>  // for uint32_t etc
#include <initializer_list>
#include <iosfwd>  // for future serialisation
#include <new>     // for placement in moves etc
#include <type_traits>

#if __cplusplus >= 201700 || _HAS_CXX17
#include <utility>  // for in_place_type_t

BOOST_OUTCOME_V2_NAMESPACE_BEGIN
template <class T> using in_place_type_t = std::in_place_type_t<T>;
using std::in_place_type;
BOOST_OUTCOME_V2_NAMESPACE_END
#else
BOOST_OUTCOME_V2_NAMESPACE_BEGIN
//! Aliases `std::in_place_type_t<T>` if on C++ 17 or later, else defined locally.
template <class T> struct in_place_type_t
{
  explicit in_place_type_t() = default;
};
//! Aliases `std::in_place_type<T>` if on C++ 17 or later, else defined locally.
template <class T> constexpr in_place_type_t<T> in_place_type{};
BOOST_OUTCOME_V2_NAMESPACE_END
#endif

BOOST_OUTCOME_V2_NAMESPACE_BEGIN
namespace detail
{
  // Test if type is an in_place_type_t
  template <class T> struct is_in_place_type_t
  {
    static constexpr bool value = false;
  };
  template <class U> struct is_in_place_type_t<in_place_type_t<U>>
  {
    static constexpr bool value = true;
  };

  // Replace void with constructible void_type
  struct empty_type
  {
  };
  struct void_type
  {
    // We always compare true to another instance of me
    constexpr bool operator==(void_type /*unused*/) const noexcept { return true; }
    constexpr bool operator!=(void_type /*unused*/) const noexcept { return false; }
  };
  template <class T> using devoid = std::conditional_t<std::is_void<T>::value, void_type, T>;

  template <class Output, class Input> using rebind_type5 = Output;
  template <class Output, class Input>
  using rebind_type4 = std::conditional_t<                                   //
  std::is_volatile<Input>::value,                                            //
  std::add_volatile_t<rebind_type5<Output, std::remove_volatile_t<Input>>>,  //
  rebind_type5<Output, Input>>;
  template <class Output, class Input>
  using rebind_type3 = std::conditional_t<                             //
  std::is_const<Input>::value,                                         //
  std::add_const_t<rebind_type4<Output, std::remove_const_t<Input>>>,  //
  rebind_type4<Output, Input>>;
  template <class Output, class Input>
  using rebind_type2 = std::conditional_t<                                            //
  std::is_lvalue_reference<Input>::value,                                             //
  std::add_lvalue_reference_t<rebind_type3<Output, std::remove_reference_t<Input>>>,  //
  rebind_type3<Output, Input>>;
  template <class Output, class Input>
  using rebind_type = std::conditional_t<                                             //
  std::is_rvalue_reference<Input>::value,                                             //
  std::add_rvalue_reference_t<rebind_type2<Output, std::remove_reference_t<Input>>>,  //
  rebind_type2<Output, Input>>;

  // static_assert(std::is_same_v<rebind_type<int, volatile const double &&>, volatile const int &&>, "");


  /* True if type is the same or constructible. Works around a bug where clang + libstdc++
  pukes on std::is_constructible<filesystem::path, void> (this bug is fixed upstream).
  */
  template <class T, class U> struct _is_explicitly_constructible
  {
    static constexpr bool value = std::is_constructible<T, U>::value;
  };
  template <class T> struct _is_explicitly_constructible<T, void>
  {
    static constexpr bool value = false;
  };
  template <> struct _is_explicitly_constructible<void, void>
  {
    static constexpr bool value = false;
  };
  template <class T, class U> static constexpr bool is_explicitly_constructible = _is_explicitly_constructible<T, U>::value;

  template <class T, class U> struct _is_implicitly_constructible
  {
    static constexpr bool value = std::is_convertible<U, T>::value;
  };
  template <class T> struct _is_implicitly_constructible<T, void>
  {
    static constexpr bool value = false;
  };
  template <> struct _is_implicitly_constructible<void, void>
  {
    static constexpr bool value = false;
  };
  template <class T, class U> static constexpr bool is_implicitly_constructible = _is_implicitly_constructible<T, U>::value;

// True if type is nothrow swappable
#if !defined(STANDARDESE_IS_IN_THE_HOUSE) && (_HAS_CXX17 || __cplusplus >= 201700)
  template <class T> using is_nothrow_swappable = std::is_nothrow_swappable<T>;
#else
  namespace _is_nothrow_swappable
  {
    using namespace std;
    template <class T> constexpr inline T &ldeclval();
    template <class T, class = void> struct is_nothrow_swappable : std::integral_constant<bool, false>
    {
    };
    template <class T> struct is_nothrow_swappable<T, decltype(swap(ldeclval<T>(), ldeclval<T>()))> : std::integral_constant<bool, noexcept(swap(ldeclval<T>(), ldeclval<T>()))>
    {
    };
  }  // namespace _is_nothrow_swappable
  template <class T> using is_nothrow_swappable = _is_nothrow_swappable::is_nothrow_swappable<T>;
#endif
}  // namespace detail
BOOST_OUTCOME_V2_NAMESPACE_END

#ifndef BOOST_OUTCOME_THROW_EXCEPTION
#include <boost/throw_exception.hpp>
#define BOOST_OUTCOME_THROW_EXCEPTION(expr) BOOST_THROW_EXCEPTION(expr)
#endif

#ifndef BOOST_OUTCOME_AUTO_TEST_CASE
#define BOOST_OUTCOME_AUTO_TEST_CASE(a, b) BOOST_AUTO_TEST_CASE(a)
#endif

#endif
