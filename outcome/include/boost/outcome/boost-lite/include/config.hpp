/* Configure Boost-lite
(C) 2016-2017 Niall Douglas <http://www.nedproductions.biz/> (8 commits)


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

#ifndef BOOSTLITE_CONFIG_HPP
#define BOOSTLITE_CONFIG_HPP

#include "revision.hpp"
#include "cpp_feature.h"

#define BOOSTLITE_VERSION_GLUE2(a, b) a##b
#define BOOSTLITE_VERSION_GLUE(a, b) BOOSTLITE_VERSION_GLUE2(a, b)

// clang-format off
#ifdef DOXYGEN_IS_IN_THE_HOUSE
//! \brief The boost-lite namespace
namespace boost_lite
{
  //! \brief Per commit unique inline namespace
  inline namespace _xxx
  {
  }
}
#define BOOSTLITE_NAMESPACE boost_lite::_xxx
#define BOOSTLITE_NAMESPACE_BEGIN namespace boost_lite { inline namespace _xxx {
#define BOOSTLITE_NAMESPACE_END } }
#else
#define BOOSTLITE_NAMESPACE boost_lite::BOOSTLITE_VERSION_GLUE(_, BOOSTLITE_PREVIOUS_COMMIT_UNIQUE)
#define BOOSTLITE_NAMESPACE_BEGIN namespace boost_lite { inline namespace BOOSTLITE_VERSION_GLUE(_, BOOSTLITE_PREVIOUS_COMMIT_UNIQUE) {
#define BOOSTLITE_NAMESPACE_END } }
#endif
// clang-format on

#ifdef _MSC_VER
#define BOOSTLITE_BIND_MESSAGE_PRAGMA2(x) __pragma(message(x))
#define BOOSTLITE_BIND_MESSAGE_PRAGMA(x) BOOSTLITE_BIND_MESSAGE_PRAGMA2(x)
#define BOOSTLITE_BIND_MESSAGE_PREFIX(type) __FILE__ "(" BOOSTLITE_BIND_STRINGIZE2(__LINE__) "): " type ": "
#define BOOSTLITE_BIND_MESSAGE_(type, prefix, msg) BOOSTLITE_BIND_MESSAGE_PRAGMA(prefix msg)
#else
#define BOOSTLITE_BIND_MESSAGE_PRAGMA2(x) _Pragma(#x)
#define BOOSTLITE_BIND_MESSAGE_PRAGMA(type, x) BOOSTLITE_BIND_MESSAGE_PRAGMA2(type x)
#define BOOSTLITE_BIND_MESSAGE_(type, prefix, msg) BOOSTLITE_BIND_MESSAGE_PRAGMA(type, msg)
#endif
//! Have the compiler output a message
#define BOOSTLITE_MESSAGE(msg) BOOSTLITE_BIND_MESSAGE_(message, BOOSTLITE_BIND_MESSAGE_PREFIX("message"), msg)
//! Have the compiler output a note
#define BOOSTLITE_NOTE(msg) BOOSTLITE_BIND_MESSAGE_(message, BOOSTLITE_BIND_MESSAGE_PREFIX("note"), msg)
//! Have the compiler output a warning
#define BOOSTLITE_WARNING(msg) BOOSTLITE_BIND_MESSAGE_(GCC warning, BOOSTLITE_BIND_MESSAGE_PREFIX("warning"), msg)
//! Have the compiler output an error
#define BOOSTLITE_ERROR(msg) BOOSTLITE_BIND_MESSAGE_(GCC error, BOOSTLITE_BIND_MESSAGE_PREFIX("error"), msg)


#ifdef BOOSTLITE_ENABLE_VALGRIND
#include "../valgrind/drd.h"
#define BOOSTLITE_ANNOTATE_RWLOCK_CREATE(p) ANNOTATE_RWLOCK_CREATE(p)
#define BOOSTLITE_ANNOTATE_RWLOCK_DESTROY(p) ANNOTATE_RWLOCK_DESTROY(p)
#define BOOSTLITE_ANNOTATE_RWLOCK_ACQUIRED(p, s) ANNOTATE_RWLOCK_ACQUIRED(p, s)
#define BOOSTLITE_ANNOTATE_RWLOCK_RELEASED(p, s) ANNOTATE_RWLOCK_RELEASED(p, s)
#define BOOSTLITE_ANNOTATE_IGNORE_READS_BEGIN() ANNOTATE_IGNORE_READS_BEGIN()
#define BOOSTLITE_ANNOTATE_IGNORE_READS_END() ANNOTATE_IGNORE_READS_END()
#define BOOSTLITE_ANNOTATE_IGNORE_WRITES_BEGIN() ANNOTATE_IGNORE_WRITES_BEGIN()
#define BOOSTLITE_ANNOTATE_IGNORE_WRITES_END() ANNOTATE_IGNORE_WRITES_END()
#define BOOSTLITE_DRD_IGNORE_VAR(x) DRD_IGNORE_VAR(x)
#define BOOSTLITE_DRD_STOP_IGNORING_VAR(x) DRD_STOP_IGNORING_VAR(x)
#define BOOSTLITE_RUNNING_ON_VALGRIND RUNNING_ON_VALGRIND
#else
#define BOOSTLITE_ANNOTATE_RWLOCK_CREATE(p)
#define BOOSTLITE_ANNOTATE_RWLOCK_DESTROY(p)
#define BOOSTLITE_ANNOTATE_RWLOCK_ACQUIRED(p, s)
#define BOOSTLITE_ANNOTATE_RWLOCK_RELEASED(p, s)
#define BOOSTLITE_ANNOTATE_IGNORE_READS_BEGIN()
#define BOOSTLITE_ANNOTATE_IGNORE_READS_END()
#define BOOSTLITE_ANNOTATE_IGNORE_WRITES_BEGIN()
#define BOOSTLITE_ANNOTATE_IGNORE_WRITES_END()
#define BOOSTLITE_DRD_IGNORE_VAR(x)
#define BOOSTLITE_DRD_STOP_IGNORING_VAR(x)
#define BOOSTLITE_RUNNING_ON_VALGRIND (0)
#endif

#ifndef BOOSTLITE_IN_THREAD_SANITIZER
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define BOOSTLITE_IN_THREAD_SANITIZER 1
#endif
#elif defined(__SANITIZE_ADDRESS__)
#define BOOSTLITE_IN_THREAD_SANITIZER 1
#endif
#endif
#ifndef BOOSTLITE_IN_THREAD_SANITIZER
#define BOOSTLITE_IN_THREAD_SANITIZER 0
#endif

#if BOOSTLITE_IN_THREAD_SANITIZER
#define BOOSTLITE_DISABLE_THREAD_SANITIZE __attribute__((no_sanitize_thread))
#else
#define BOOSTLITE_DISABLE_THREAD_SANITIZE
#endif

#ifndef BOOSTLITE_SMT_PAUSE
#if !defined(__clang__) && defined(_MSC_VER) && _MSC_VER >= 1310 && (defined(_M_IX86) || defined(_M_X64))
extern "C" void _mm_pause();
#pragma intrinsic(_mm_pause)
#define BOOSTLITE_SMT_PAUSE _mm_pause();
#elif !defined(__c2__) && defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define BOOSTLITE_SMT_PAUSE __asm__ __volatile__("rep; nop" : : : "memory");
#endif
#endif

// TO BE REMOVED SOON: C++ 14 constexpr macro
#ifndef BOOSTLITE_CONSTEXPR
#if __cpp_constexpr >= 201304
#define BOOSTLITE_CONSTEXPR constexpr
#endif
#endif
#ifndef BOOSTLITE_CONSTEXPR
#define BOOSTLITE_CONSTEXPR
#endif

#ifndef BOOSTLITE_FORCEINLINE
#if defined(_MSC_VER)
#define BOOSTLITE_FORCEINLINE __forceinline
#elif defined(__GNUC__)
#define BOOSTLITE_FORCEINLINE __attribute__((always_inline))
#else
#define BOOSTLITE_FORCEINLINE
#endif
#endif

#ifndef BOOSTLITE_NOINLINE
#if defined(_MSC_VER)
#define BOOSTLITE_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
#define BOOSTLITE_NOINLINE __attribute__((noinline))
#else
#define BOOSTLITE_NOINLINE
#endif
#endif

#if !defined(BOOSTLITE_NORETURN)
#ifdef __cpp_attributes
#define BOOSTLITE_NORETURN [[noreturn]]
#elif defined(_MSC_VER)
#define BOOSTLITE_NORETURN __declspec(noreturn)
#elif defined(__GNUC__)
#define BOOSTLITE_NORETURN __attribute__((__noreturn__))
#else
#define BOOSTLITE_NORETURN
#endif
#endif

#ifndef BOOSTLITE_NODISCARD
#ifdef __has_cpp_attribute
#if __has_cpp_attribute(nodiscard)
#define BOOSTLITE_NODISCARD [[nodiscard]]
#endif
#elif defined(__clang__)
#define BOOSTLITE_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
// _Must_inspect_result_ expands into this
#define BOOSTLITE_NODISCARD                                                                                                                                                                                                                                                                                                  \
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
#ifndef BOOSTLITE_NODISCARD
#define BOOSTLITE_NODISCARD
#endif

#ifndef BOOSTLITE_SYMBOL_VISIBLE
#if defined(_MSC_VER)
#define BOOSTLITE_SYMBOL_VISIBLE
#elif defined(__GNUC__)
#define BOOSTLITE_SYMBOL_VISIBLE __attribute__((visibility("default")))
#else
#define BOOSTLITE_SYMBOL_VISIBLE
#endif
#endif

#ifndef BOOSTLITE_SYMBOL_EXPORT
#if defined(_MSC_VER)
#define BOOSTLITE_SYMBOL_EXPORT __declspec(dllexport)
#elif defined(__GNUC__)
#define BOOSTLITE_SYMBOL_EXPORT __attribute__((visibility("default")))
#else
#define BOOSTLITE_SYMBOL_EXPORT
#endif
#endif

#ifndef BOOSTLITE_SYMBOL_IMPORT
#if defined(_MSC_VER)
#define BOOSTLITE_SYMBOL_IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
#define BOOSTLITE_SYMBOL_IMPORT
#else
#define BOOSTLITE_SYMBOL_IMPORT
#endif
#endif

#ifndef BOOSTLITE_THREAD_LOCAL
#if __cplusplus >= 201103L
#define BOOSTLITE_THREAD_LOCAL thread_local
#elif defined(_MSC_VER)
#define BOOSTLITE_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__)
#define BOOSTLITE_THREAD_LOCAL __thread
#else
#error Unknown compiler, cannot set BOOSTLITE_THREAD_LOCAL
#endif
#endif

#endif
