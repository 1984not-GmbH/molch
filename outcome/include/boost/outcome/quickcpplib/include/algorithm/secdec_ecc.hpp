/* String algorithms
(C) 2016-2017 Niall Douglas <http://www.nedproductions.biz/> (3 commits)
File Created: Jun 2016


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

#ifndef QUICKCPPLIB_ALGORITHM_SECDEC_ECC_HPP
#define QUICKCPPLIB_ALGORITHM_SECDEC_ECC_HPP

#include "../config.hpp"

QUICKCPPLIB_NAMESPACE_BEGIN

namespace algorithm
{
  namespace secdec_ecc
  {
#ifndef QUICKCPPLIB_SECDEC_INTRINSICS
#if defined(__GCC__) || defined(__clang__)
#define QUICKCPPLIB_SECDEC_INTRINSICS 1
#elif defined(_MSC_VER) && (defined(_M_X64) || _M_IX86_FP == 1)
#define QUICKCPPLIB_SECDEC_INTRINSICS 1
#endif
#endif
#ifndef QUICKCPPLIB_SECDEC_INTRINSICS
#define QUICKCPPLIB_SECDEC_INTRINSICS 0
#endif
    /*! \class secded_ecc
    \brief Calculates the single error correcting double error detecting (SECDED) Hamming Error Correcting Code for a \em blocksize block of bytes. For example, a secdec_ecc<8> would be the very common 72,64 Hamming code used in ECC RAM, or secdec_ecc<4096> would be for a 32784,32768 Hamming code.

    Did you know that some non-ECC RAM systems can see 1e-12 flips/bit/hour, which is 3.3 bits flipped in a 16Gb RAM system
    per 24 hours). See Schroeder, Pinheiro and Weber (2009) 'DRAM Errors in the Wild: A Large-Scale Field Study'.

    After construction during which lookup tables are built, no state is modified and therefore this class is safe for static
    storage (indeed if C++ 14 is available, the constructor is constexpr). The maximum number of bits in a code is a good four
    billion, I did try limiting it to 65536 for performance but it wasn't worth it, and one might want > 8Kb blocks maybe.
    As with all SECDED ECC, undefined behaviour occurs when more than two bits of error are present or the ECC supplied
    is incorrect. You should combine this SECDED with a robust hash which can tell you definitively if a buffer is error
    free or not rather than relying on this to correctly do so.

    The main intended use case for this routine is calculating the ECC on data being written to disc, and hence that is
    where performance has been maximised. It is not expected that this routine will be frequently called on data being read
    from disc i.e. only when its hash doesn't match its contents which should be very rare, and then a single bit heal using this routine is attempted
    before trying again with the hash. Care was taken that really enormous SECDEDs are fast, in fact tuning was mostly
    done for the 32784,32768 code which can heal one bad bit per 4Kb page as the main thing we have in mind is achieving
    reliable filing system code on computers without ECC RAM and in which sustained large quantities of random disc i/o produce
    a worrying number of flipped bits in a 24 hour period (anywhere between 0 and 3 on my hardware here, average is about 0.8).

    Performance of the fixed block size routine where you supply whole chunks of \em blocksize is therefore \b particularly excellent
    as I spent a lot of time tuning it for Ivy Bridge and later out of order architectures: an
    amazing 22 cycles per byte for the 32784,32768 code, which is a testament to modern out of order CPUs (remember SECDED inherently must work a bit
    at a time, so that's just 2.75 amortised CPU cycles per bit which includes a table load, a bit test, and a conditional XOR)
    i.e. it's pushing about 1.5 ops per clock cycle. On my 3.9Ghz i7-3770K here, I see about 170Mb/sec per CPU core.

    The variable length routine is necessarily much slower as it must work in single bytes, and achieves 72 cycles per byte,
    or 9 cycles per bit (64Mb/sec per CPU core).

    \ingroup utils
    \complexity{O(N) where N is the blocksize}
    \exceptionmodel{Throws constexpr exceptions in constructor only, otherwise entirely noexcept.}
    */
    template <size_t blocksize> class secded_ecc
    {
    public:
      typedef unsigned int result_type;  //!< The largest ECC which can be calculated
    private:
      static constexpr size_t bits_per_byte = 8;
      typedef unsigned char unit_type;  // The batch unit of processing
      result_type bitsvalid;
      // Many CPUs (x86) are slow doing variable bit shifts, so keep a table
      result_type ecc_twospowers[sizeof(result_type) * bits_per_byte];
      unsigned short ecc_table[blocksize * bits_per_byte];
      static bool _is_single_bit_set(result_type x)
      {
#ifndef _MSC_VER
#if defined(__i386__) || defined(__x86_64__)
#ifndef __SSE4_2__
        // Do a once off runtime check
        static int have_popcnt = [] {
          size_t cx, dx;
#if defined(__x86_64__)
          asm("cpuid" : "=c"(cx), "=d"(dx) : "a"(1), "b"(0), "c"(0), "d"(0));
#else
          asm("pushl %%ebx\n\tcpuid\n\tpopl %%ebx\n\t" : "=c"(cx), "=d"(dx) : "a"(1), "c"(0), "d"(0));
#endif
          return (dx & (1 << 26)) != 0 /*SSE2*/ && (cx & (1 << 23)) != 0 /*POPCNT*/;
        }();
        if(have_popcnt)
#endif
        {
          unsigned count;
          asm("popcnt %1,%0" : "=r"(count) : "rm"(x) : "cc");
          return count == 1;
        }
#endif
        return __builtin_popcount(x) == 1;
#else
        x -= (x >> 1) & 0x55555555;
        x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
        x = (x + (x >> 4)) & 0x0f0f0f0f;
        unsigned int count = (x * 0x01010101) >> 24;
        return count == 1;
#if 0
        x -= (x >> 1) & 0x5555555555555555ULL;
        x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
        x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
        unsigned long long count = (x * 0x0101010101010101ULL) >> 56;
        return count == 1;
#endif
#endif
      }

    public:
      //! Constructs an instance, configuring the necessary lookup tables
      QUICKCPPLIB_CONSTEXPR secded_ecc()
      {
        for(size_t n = 0; n < sizeof(result_type) * bits_per_byte; n++)
          ecc_twospowers[n] = ((result_type) 1 << n);
        result_type length = blocksize * bits_per_byte;
        // This is (data bits + parity bits + 1) <= 2^(parity bits)
        for(result_type p = 1; p < sizeof(result_type) * bits_per_byte; p++)
          if((length + p + 1) <= ecc_twospowers[p])
          {
            bitsvalid = p;
            break;
          }
        if((bits_per_byte - 1 + bitsvalid) / bits_per_byte > sizeof(result_type))
          throw std::runtime_error("secdec_ecc: ECC would exceed the size of result_type!");
        for(result_type i = 0; i < blocksize * bits_per_byte; i++)
        {
          // Make a code bit
          result_type b = i + 1;
#if QUICKCPPLIB_SECDEC_INTRINSICS && 0  // let constexpr do its thing
#ifdef _MSC_VER
          unsigned long _topbit;
          _BitScanReverse(&_topbit, b);
          result_type topbit = _topbit;
#else
          result_type topbit = bits_per_byte * sizeof(result_type) - __builtin_clz(b);
#endif
          b += topbit;
          if(b >= ecc_twospowers[topbit])
            b++;
// while(b>ecc_twospowers(_topbit+1)) _topbit++;
// b+=_topbit;
// if(b>=ecc_twospowers(_topbit)) b++;
#else
          for(size_t p = 0; ecc_twospowers[p] < (b + 1); p++)
            b++;
#endif
          ecc_table[i] = (unsigned short) b;
          if(b > (unsigned short) -1)
            throw std::runtime_error("secdec_ecc: Precalculated table has exceeded its bounds");
        }
      }
      //! The number of bits valid in result_type
      constexpr result_type result_bits_valid() const noexcept { return bitsvalid; }
      //! Accumulate ECC from fixed size buffer
      result_type operator()(result_type ecc, const char *buffer) const noexcept
      {
        if(blocksize < sizeof(unit_type) * 8)
          return (*this)(ecc, buffer, blocksize);
        // Process in lumps of eight
        const unit_type *_buffer = (const unit_type *) buffer;
        //#pragma omp parallel for reduction(^:ecc)
        for(size_t i = 0; i < blocksize; i += sizeof(unit_type) * 8)
        {
          union {
            unsigned long long v;
            unit_type c[8];
          };
          result_type prefetch[8];
          v = *(unsigned long long *) (&_buffer[0 + i / sizeof(unit_type)]);  // min 1 cycle
#define QUICKCPPLIB_SECDEC_ROUND(n)                                                                                                                                                                                                                                                                                              \
  prefetch[0] = ecc_table[(i + 0) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[1] = ecc_table[(i + 1) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[2] = ecc_table[(i + 2) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[3] = ecc_table[(i + 3) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[4] = ecc_table[(i + 4) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[5] = ecc_table[(i + 5) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[6] = ecc_table[(i + 6) * 8 + n];                                                                                                                                                                                                                                                                                    \
  prefetch[7] = ecc_table[(i + 7) * 8 + n];                                                                                                                                                                                                                                                                                    \
  if(c[0] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[0];                                                                                                                                                                                                                                                                                                        \
  if(c[1] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[1];                                                                                                                                                                                                                                                                                                        \
  if(c[2] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[2];                                                                                                                                                                                                                                                                                                        \
  if(c[3] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[3];                                                                                                                                                                                                                                                                                                        \
  if(c[4] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[4];                                                                                                                                                                                                                                                                                                        \
  if(c[5] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[5];                                                                                                                                                                                                                                                                                                        \
  if(c[6] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[6];                                                                                                                                                                                                                                                                                                        \
  if(c[7] & ((unit_type) 1 << n))                                                                                                                                                                                                                                                                                              \
    ecc ^= prefetch[7];
          QUICKCPPLIB_SECDEC_ROUND(0)  // prefetch = min 8, bit test and xor = min 16, total = 24
          QUICKCPPLIB_SECDEC_ROUND(1)
          QUICKCPPLIB_SECDEC_ROUND(2)
          QUICKCPPLIB_SECDEC_ROUND(3)
          QUICKCPPLIB_SECDEC_ROUND(4)
          QUICKCPPLIB_SECDEC_ROUND(5)
          QUICKCPPLIB_SECDEC_ROUND(6)
          QUICKCPPLIB_SECDEC_ROUND(7)
#undef QUICKCPPLIB_SECDEC_ROUND  // total should be 1+(8*24/3)=65
        }
        return ecc;
      }
      result_type operator()(const char *buffer) const noexcept { return (*this)(0, buffer); }
      //! Accumulate ECC from partial buffer where \em length <= \em blocksize
      result_type operator()(result_type ecc, const char *buffer, size_t length) const noexcept
      {
        const unit_type *_buffer = (const unit_type *) buffer;
        //#pragma omp parallel for reduction(^:ecc)
        for(size_t i = 0; i < length; i += sizeof(unit_type))
        {
          unit_type c = _buffer[i / sizeof(unit_type)];  // min 1 cycle
          if(!c)                                         // min 1 cycle
            continue;
          char bitset[bits_per_byte * sizeof(unit_type)];
          result_type prefetch[bits_per_byte * sizeof(unit_type)];
          // Most compilers will roll this out
          for(size_t n = 0; n < bits_per_byte * sizeof(unit_type); n++)  // min 16 cycles
          {
            bitset[n] = !!(c & ((unit_type) 1 << n));
            prefetch[n] = ecc_table[i * bits_per_byte + n];  // min 8 cycles
          }
          result_type localecc = 0;
          for(size_t n = 0; n < bits_per_byte * sizeof(unit_type); n++)
          {
            if(bitset[n])               // min 8 cycles
              localecc ^= prefetch[n];  // min 8 cycles
          }
          ecc ^= localecc;  // min 1 cycle. Total cycles = min 43 cycles/byte
        }
        return ecc;
      }
      result_type operator()(const char *buffer, size_t length) const noexcept { return (*this)(0, buffer, length); }
      //! Given the original ECC and the new ECC for a buffer, find the bad bit. Return (result_type)-1 if not found (e.g. ECC corrupt)
      result_type find_bad_bit(result_type good_ecc, result_type bad_ecc) const noexcept
      {
        result_type length = blocksize * bits_per_byte, eccdiff = good_ecc ^ bad_ecc;
        if(_is_single_bit_set(eccdiff))
          return (result_type) -1;
        for(result_type i = 0, b = 1; i < length; i++, b++)
        {
          // Skip parity bits
          while(_is_single_bit_set(b))
            b++;
          if(b == eccdiff)
            return i;
        }
        return (result_type) -1;
      }
      //! The outcomes from verify()
      enum verify_status
      {
        corrupt = 0,  //!< The buffer had more than a single bit corrupted or the ECC was invalid
        okay = 1,     //!< The buffer had no errors
        healed = 2    //!< The buffer was healed
      };
      //! Verifies and heals when possible a buffer, returning non zero if the buffer is error free
      verify_status verify(char *buffer, result_type good_ecc) const noexcept
      {
        result_type this_ecc = (*this)(0, buffer);
        if(this_ecc == good_ecc)
          return verify_status::okay;  // no errors
        result_type badbit = find_bad_bit(good_ecc, this_ecc);
        if((result_type) -1 == badbit)
          return verify_status::corrupt;  // parity corrupt?
        buffer[badbit / bits_per_byte] ^= (unsigned char) ecc_twospowers[badbit % bits_per_byte];
        this_ecc = (*this)(0, buffer);
        if(this_ecc == good_ecc)
          return healed;  // error healed
                          // Put the bit back
        buffer[badbit / bits_per_byte] ^= (unsigned char) ecc_twospowers[badbit % bits_per_byte];
        return verify_status::corrupt;  // more than one bit was corrupt
      }
    };
  }
}

QUICKCPPLIB_NAMESPACE_END

#endif
