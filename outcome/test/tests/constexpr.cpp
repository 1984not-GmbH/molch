/* Unit testing for outcomes
(C) 2013-2017 Niall Douglas <http://www.nedproductions.biz/> (149 commits)


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

#include "../../include/outcome/outcome.hpp"
#include "quickcpplib/include/boost/test/unit_test.hpp"

BOOST_OUTCOME_AUTO_TEST_CASE(works / outcome / constexpr, "Tests that outcome works as intended in a constexpr evaluation context")
{
  using namespace OUTCOME_V2_NAMESPACE;

  static_assert(std::is_literal_type<result<int, void, void>>::value, "result<int, void, void> is not a literal type!");
  static_assert(std::is_literal_type<outcome<int, void, void>>::value, "outcome<int, void, void> is not a literal type!");

  // Unfortunately result<T> can never be a literal type as error_code can never be literal
  //
  // It can however be trivially destructible as error_code is trivially destructible. That
  // makes possible lots of compiler optimisations
  static_assert(!std::is_literal_type<result<int>>::value, "result<int> is a literal type!");
  static_assert(std::is_trivially_destructible<result<int>>::value, "result<int> is not trivially destructible!");
  static_assert(std::is_trivially_destructible<result<void>>::value, "result<void> is not trivially destructible!");

  // outcome<T> default has no trivial operations, but if configured it can become so
  static_assert(std::is_trivially_destructible<outcome<int, std::error_code, void>>::value, "outcome<int, std::error_code, void> is not trivially destructible!");

  {
    // Test compatible results can be constructed from one another
    constexpr result<int, long> g(in_place_type<int>, 5);
    constexpr result<long, int> g2(g);
    static_assert(g.has_value(), "");
    static_assert(!g.has_error(), "");
    static_assert(g.value() == 5, "");
    static_assert(g2.has_value(), "");
    static_assert(!g2.has_error(), "");
    static_assert(g2.value() == 5, "");
    constexpr result<void, int> g3(in_place_type<void>);
    constexpr result<long, int> g4(g3);
    constexpr result<int, void> g5(in_place_type<void>);
    constexpr result<long, int> g6(g5);

    // Test void
    constexpr result<void, int> h(in_place_type<void>);
    static_assert(h.has_value(), "");
    constexpr result<int, void> h2(in_place_type<void>);
    static_assert(!h2.has_value(), "");
    static_assert(h2.has_error(), "");

    // Test const
    constexpr result<const int, void> i(5);
    constexpr result<const int, void> i2(i);
    (void) i2;
  }
  {
    // Test compatible outcomes can be constructed from one another
    constexpr outcome<int, long, char *> g(in_place_type<int>, 5);
    constexpr outcome<long, int, const char *> g2(g);
    static_assert(g.has_value(), "");
    static_assert(!g.has_error(), "");
    static_assert(!g.has_exception(), "");
    static_assert(g.value() == 5, "");
    static_assert(g2.has_value(), "");
    static_assert(!g2.has_error(), "");
    static_assert(!g2.has_exception(), "");
    static_assert(g2.value() == 5, "");
    constexpr outcome<void, int, char *> g3(in_place_type<void>);
    constexpr outcome<long, int, const char *> g4(g3);
    constexpr outcome<int, void, char *> g5(in_place_type<void>);
    constexpr outcome<long, int, const char *> g6(g5);
  }
}
