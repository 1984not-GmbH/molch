/* Small PRNG
(C) 2016-2017 Niall Douglas <http://www.nedproductions.biz/> (3 commits)
File Created: Sept 2016


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

#ifndef BOOSTLITE_ALGORITHM_SMALL_PRNG_HPP
#define BOOSTLITE_ALGORITHM_SMALL_PRNG_HPP

#include "../utils/thread.hpp"

#include <cstdint>
#include <iterator>

BOOSTLITE_NAMESPACE_BEGIN

namespace algorithm
{
  namespace small_prng
  {
    /*! \class small_prng
    \brief From http://burtleburtle.net/bob/rand/smallprng.html
    */
    class small_prng
    {
      uint32_t a;
      uint32_t b;
      uint32_t c;
      uint32_t d;

      static inline uint32_t rot(uint32_t x, uint32_t k) noexcept { return (((x) << (k)) | ((x) >> (32 - (k)))); }
    public:
      explicit small_prng(uint32_t seed = 0xdeadbeef) noexcept
      {
        a = 0xf1ea5eed;
        b = c = d = seed;
        for(size_t i = 0; i < 20; ++i)
          (*this)();
      }

      inline uint32_t operator()() noexcept
      {
        uint32_t e = a - rot(b, 27);
        a = b ^ rot(c, 17);
        b = c + d;
        c = d + e;
        d = e + a;
        return d;
      }
    };

    //! \brief A thread safe small prng seeded with the thread id
    inline small_prng &thread_local_prng()
    {
      static thread_local small_prng v(utils::thread::this_thread_id());
      return v;
    }

    template <class RandomIt> void random_shuffle(RandomIt first, RandomIt last, small_prng &r = thread_local_prng())
    {
      typename std::iterator_traits<RandomIt>::difference_type i, n;
      n = last - first;
      for(i = n - 1; i > 0; --i)
      {
        using std::swap;
        swap(first[i], first[r() % (i + 1)]);
      }
    }
  }
}

BOOSTLITE_NAMESPACE_END

#endif
