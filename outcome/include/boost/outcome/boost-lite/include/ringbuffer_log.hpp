/* Very fast threadsafe ring buffer log
(C) 2016-2017 Niall Douglas <http://www.nedproductions.biz/> (21 commits)
File Created: Mar 2016


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

#ifndef BOOSTLITE_RINGBUFFER_LOG_HPP
#define BOOSTLITE_RINGBUFFER_LOG_HPP

#ifndef BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_DEBUG
#define BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_DEBUG 4096
#endif

#ifndef BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_NDEBUG
#define BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_NDEBUG 256
#endif

#ifdef NDEBUG
#define BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_NDEBUG
#else
#define BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_DEBUG
#endif

// If I'm on winclang, I can't stop the deprecation warnings from MSVCRT unless I do this
#if defined(_MSC_VER) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "config.hpp"
#include "cpp_feature.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>  // for ptrdiff_t
#include <cstdint>  // for uint32_t etc
#include <cstring>  // for memcmp
#include <iomanip>
#include <ostream>
#include <sstream>
#include <system_error>
#include <type_traits>

#ifdef _WIN32
#include "execinfo_win64.h"
#else
#include <execinfo.h>
#endif

BOOSTLITE_NAMESPACE_BEGIN

namespace ringbuffer_log
{
  template <class Policy> class ringbuffer_log;
  //! Level of logged item
  enum class level : unsigned char
  {
    none = 0,
    fatal,
    error,
    warn,
    info,
    debug,
    all
  };

  //! Returns a const char * no more than 190 chars from its end
  template <class T> inline const char *last190(const T &v)
  {
    size_t size = v.size();
    return size <= 190 ? v.data() : v.data() + (size - 190);
  }
  namespace simple_ringbuffer_log_policy_detail
  {
    using level_ = level;
    struct value_type
    {
      uint64_t counter;
      uint64_t timestamp;
      union {
        uint32_t code32[2];
        uint64_t code64;
      };
      union {
        uint64_t backtrace[5];
        char function[40];
      };
      uint8_t level : 4;
      uint8_t using_code64 : 1;
      uint8_t using_backtrace : 1;
      char message[191];

    private:
      static std::chrono::high_resolution_clock::time_point _first_item()
      {
        static std::chrono::high_resolution_clock::time_point now = std::chrono::high_resolution_clock::now();
        return now;
      }

    public:
      value_type() { memset(this, 0, sizeof(*this)); }
      value_type(level_ _level, const char *_message, uint32_t _code1, uint32_t _code2, const char *_function = nullptr, unsigned lineno = 0)
          : counter((size_t) -1)
          , timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>((_first_item(), std::chrono::high_resolution_clock::now() - _first_item())).count())
          , code32{_code1, _code2}
          , level(static_cast<uint8_t>(_level))
          , using_code64(false)
          , using_backtrace(!_function)
      {
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)  // use of strncpy
#endif
        strncpy(message, _message, sizeof(message));
        if(_function)
        {
          if(_function[0])
          {
            strncpy(function, _function, sizeof(function));
            char temp[32], *e = function;
            for(size_t n = 0; n < sizeof(function) && *e != 0; n++, e++)
              ;
#ifdef _MSC_VER
            _ultoa_s(lineno, temp, 10);
#else
            snprintf(temp, sizeof(temp), "%u", lineno);
#endif
            temp[31] = 0;
            ptrdiff_t len = strlen(temp);
            if(function + sizeof(function) - e >= len + 2)
            {
              *e++ = ':';
              memcpy(e, temp, len);
            }
          }
        }
        else
        {
          constexpr size_t items = 1 + sizeof(backtrace) / sizeof(backtrace[0]);
          void *temp[items];
          memset(temp, 0, sizeof(temp));
          (void) ::backtrace(temp, items);
          memcpy(backtrace, temp + 1, sizeof(backtrace));
        }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
      }
      bool operator==(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) == 0; }
      bool operator!=(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) != 0; }
      bool operator<(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) < 0; }
      bool operator>(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) > 0; }
      bool operator<=(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) <= 0; }
      bool operator>=(const value_type &o) const noexcept { return memcmp(this, &o, sizeof(*this)) >= 0; }
    };
    static_assert(sizeof(value_type) == 256, "value_type is not 256 bytes long!");

    //! std::ostream writer for simple_ringbuffer_log_policy's value_type
    inline std::ostream &operator<<(std::ostream &s, const value_type &v)
    {
      s << "+" << std::setfill('0') << std::setw(16) << v.timestamp << " " << std::setfill(' ') << std::setw(1);
      switch(v.level)
      {
      case 0:
        s << "none:  ";
        break;
      case 1:
        s << "fatal: ";
        break;
      case 2:
        s << "error: ";
        break;
      case 3:
        s << "warn:  ";
        break;
      case 4:
        s << "info:  ";
        break;
      case 5:
        s << "debug: ";
        break;
      case 6:
        s << "all:   ";
        break;
      default:
        s << "unknown: ";
        break;
      }
      if(v.using_code64)
        s << "{ " << v.code64 << " } ";
      else
        s << "{ " << v.code32[0] << ", " << v.code32[1] << " } ";
      char temp[256];
      memcpy(temp, v.message, sizeof(v.message));
      temp[sizeof(v.message)] = 0;
      s << temp << " @ ";
      if(v.using_backtrace)
      {
        char **symbols = backtrace_symbols((void **) v.backtrace, sizeof(v.backtrace) / sizeof(v.backtrace[0]));
        if(!symbols)
          s << "BACKTRACE FAILED!";
        else
        {
          for(size_t n = 0; n < sizeof(v.backtrace) / sizeof(v.backtrace[0]); n++)
          {
            if(symbols[n])
            {
              if(n)
                s << ", ";
              s << symbols[n];
            }
          }
          free(symbols);
        }
      }
      else
      {
        memcpy(temp, v.function, sizeof(v.function));
        temp[sizeof(v.function)] = 0;
        s << temp;
      }
      return s << "\n";
    }
    //! CSV std::ostream writer for simple_ringbuffer_log_policy's value_type
    inline std::ostream &csv(std::ostream &s, const value_type &v)
    {
      // timestamp,level,using_code64,using_backtrace,code0,code1,message,backtrace
      s << v.timestamp << "," << (unsigned) v.level << "," << (unsigned) v.using_code64 << "," << (unsigned) v.using_backtrace << ",";
      if(v.using_code64)
        s << v.code64 << ",0,\"";
      else
        s << v.code32[0] << "," << v.code32[1] << ",\"";
      char temp[256];
      memcpy(temp, v.message, sizeof(v.message));
      temp[sizeof(v.message)] = 0;
      s << temp << "\",\"";
      if(v.using_backtrace)
      {
        char **symbols = backtrace_symbols((void **) v.backtrace, sizeof(v.backtrace) / sizeof(v.backtrace[0]));
        if(!symbols)
          s << "BACKTRACE FAILED!";
        else
        {
          for(size_t n = 0; n < sizeof(v.backtrace) / sizeof(v.backtrace[0]); n++)
          {
            if(symbols[n])
            {
              if(n)
                s << ";";
              s << symbols[n];
            }
          }
          free(symbols);
        }
      }
      else
      {
        memcpy(temp, v.function, sizeof(v.function));
        temp[sizeof(v.function)] = 0;
        s << temp;
      }
      return s << "\"\n";
    }
  }

  /*! \tparam Bytes The size of the ring buffer
  \brief A ring buffer log stored in a fixed
  BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_NDEBUG/BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES_DEBUG
  std::array recording
  monotonic counter (8 bytes), high resolution clock time stamp (8 bytes),
  stack backtrace or __func__ (40 bytes), level (1 byte), 191 bytes of
  char message. Each record is 256 bytes, therefore the ring buffer
  wraps after 256/4096 entries by default.
  */
  template <size_t Bytes = BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES * 256> struct simple_ringbuffer_log_policy
  {
    //! Item logged in this log
    using value_type = simple_ringbuffer_log_policy_detail::value_type;
    //! Maximum items of this value_type in this log
    static constexpr size_t max_items = Bytes / sizeof(value_type);
    //! Container for storing log
    using container_type = std::array<value_type, max_items>;
  };

  /*! \class ringbuffer_log
  \brief Very fast threadsafe ring buffer log

  Works on the basis of an always incrementing atomic<size_t> which writes
  into the ring buffer at modulus of the ring buffer size. Items stored per
  log entry are defined by the Policy class' value_type. To log an item,
  call the BOOSTLITE_RINGBUFFERLOG_ITEM_* family of macros.

  Be aware iteration, indexing etc. is most recent first, so log[0] is
  the most recently logged item. Use the reversed iterators if you don't
  want this.

  For simple_ringbuffer_log_policy, typical item logging times are:
  - without backtrace: 1.2 microseconds.
  - with backtrace (windows): up to 33 microseconds.

  \todo Implement STL allocator for a memory mapped file on disc so log
  survives sudden process exit.
  */
  template <class Policy> class ringbuffer_log
  {
    friend Policy;

  public:
    /*! The container used to store the logged records set by
    Policy::container_type. Must be a ContiguousContainer.
    */
    using container_type = typename Policy::container_type;
    //! The maximum items to store according to Policy::max_items. If zero, use container's size().
    static constexpr size_t max_items = Policy::max_items;

    //! The log record type
    using value_type = typename container_type::value_type;
    //! The size type
    using size_type = typename container_type::size_type;
    //! The difference type
    using difference_type = typename container_type::difference_type;
    //! The reference type
    using reference = typename container_type::reference;
    //! The const reference type
    using const_reference = typename container_type::const_reference;
    //! The pointer type
    using pointer = typename container_type::pointer;
    //! The const pointer type
    using const_pointer = typename container_type::const_pointer;

  protected:
    template <class Parent, class Pointer, class Reference> class iterator_;
    template <class Parent, class Pointer, class Reference> class iterator_ : public std::iterator<std::random_access_iterator_tag, value_type, difference_type, pointer, reference>
    {
      friend class ringbuffer_log;
      template <class Parent_, class Pointer_, class Reference_> friend class iterator_;
      Parent *_parent;
      size_type _counter, _togo;

      constexpr iterator_(Parent *parent, size_type counter, size_type items)
          : _parent(parent)
          , _counter(counter)
          , _togo(items)
      {
      }

    public:
      constexpr iterator_()
          : _parent(nullptr)
          , _counter(0)
          , _togo(0)
      {
      }
      constexpr iterator_(const iterator_ &) noexcept = default;
      constexpr iterator_(iterator_ &&) noexcept = default;
      iterator_ &operator=(const iterator_ &) noexcept = default;
      iterator_ &operator=(iterator_ &&) noexcept = default;
      // Non-const to const iterator
      template <class Parent_, class Pointer_, class Reference_, typename = typename std::enable_if<!std::is_const<Pointer_>::value && !std::is_const<Reference_>::value>::type> constexpr iterator_(const iterator_<Parent_, Pointer_, Reference_> &o) noexcept : _parent(o._parent), _counter(o._counter), _togo(o._togo) {}
      iterator_ &operator++() noexcept
      {
        if(_parent && _togo)
        {
          --_counter;
          --_togo;
        }
        return *this;
      }
      void swap(iterator_ &o) noexcept
      {
        std::swap(_parent, o._parent);
        std::swap(_counter, o._counter);
        std::swap(_togo, o._togo);
      }
      Pointer operator->() const noexcept
      {
        if(!_parent || !_togo)
          return nullptr;
        return &_parent->_store[_parent->counter_to_idx(_counter)];
      }
      bool operator==(const iterator_ &o) const noexcept { return _parent == o._parent && _counter == o._counter && _togo == o._togo; }
      bool operator!=(const iterator_ &o) const noexcept { return _parent != o._parent || _counter != o._counter || _togo != o._togo; }
      Reference operator*() const noexcept
      {
        if(!_parent || !_togo)
        {
          static value_type v;
          return v;
        }
        return _parent->_store[_parent->counter_to_idx(_counter)];
      }
      iterator_ operator++(int) noexcept
      {
        iterator_ ret(*this);
        if(_parent && _togo)
        {
          --_counter;
          --_togo;
        }
        return ret;
      }
      iterator_ &operator--() noexcept
      {
        if(_parent && _togo < _parent->size())
        {
          ++_counter;
          ++_togo;
        }
        return *this;
      }
      iterator_ operator--(int) noexcept
      {
        iterator_ ret(*this);
        if(_parent && _togo < _parent->size())
        {
          ++_counter;
          ++_togo;
        }
        return ret;
      }
      bool operator<(const iterator_ &o) const noexcept { return _parent == o._parent && _parent->counter_to_idx(_counter) < o._parent->counter_to_idx(o._counter); }
      bool operator>(const iterator_ &o) const noexcept { return _parent == o._parent && _parent->counter_to_idx(_counter) > o._parent->counter_to_idx(o._counter); }
      bool operator<=(const iterator_ &o) const noexcept { return _parent == o._parent && _parent->counter_to_idx(_counter) <= o._parent->counter_to_idx(o._counter); }
      bool operator>=(const iterator_ &o) const noexcept { return _parent == o._parent && _parent->counter_to_idx(_counter) >= o._parent->counter_to_idx(o._counter); }
      iterator_ &operator+=(size_type v) const noexcept
      {
        if(_parent && _togo)
        {
          if(v > _togo)
            v = _togo;
          _counter -= v;
          _togo -= v;
        }
        return *this;
      }
      iterator_ operator+(size_type v) const noexcept
      {
        iterator_ ret(*this);
        if(_parent && _togo)
        {
          if(v > _togo)
            v = _togo;
          ret._counter -= v;
          ret._togo -= v;
        }
        return ret;
      }
      iterator_ &operator-=(size_type v) const noexcept
      {
        if(_parent && _togo < _parent->size())
        {
          if(v > _parent->size() - _togo)
            v = _parent->size() - _togo;
          _counter += v;
          _togo += v;
        }
        return *this;
      }
      iterator_ operator-(size_type v) const noexcept
      {
        iterator_ ret(*this);
        if(_parent && _togo < _parent->size())
        {
          if(v > _parent->size() - _togo)
            v = _parent->size() - _togo;
          ret._counter += v;
          ret._togo += v;
        }
        return ret;
      }
      difference_type operator-(const iterator_ &o) const noexcept { return (difference_type)(o._counter - _counter); }
      Reference operator[](size_type v) const noexcept { return _parent->_store[_parent->counter_to_idx(_counter + v)]; }
    };
    template <class Parent, class Pointer, class Reference> friend class iterator_;

  public:
    //! The iterator type
    using iterator = iterator_<ringbuffer_log, pointer, reference>;
    //! The const iterator type
    using const_iterator = iterator_<const ringbuffer_log, const_pointer, const_reference>;
    //! The reverse iterator type
    using reverse_iterator = std::reverse_iterator<iterator>;
    //! The const reverse iterator type
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  protected:
    container_type _store;
    level _level;
    std::atomic<size_type> _counter;
    std::ostream *_immediate;

    size_type counter_to_idx(size_type counter) const noexcept { return max_items ? (counter % max_items) : (counter % _store.size()); }
  public:
    //! Default construction, passes through args to container_type
    template <class... Args>
    ringbuffer_log(level starting_level, Args &&... args)
        : _store(std::forward<Args>(args)...)
        , _level(starting_level)
        , _counter(0)
        , _immediate(nullptr)
    {
    }
    //! No copying
    ringbuffer_log(const ringbuffer_log &) = delete;
    //! No moving
    ringbuffer_log(ringbuffer_log &&) = delete;
    //! No copying
    ringbuffer_log &operator=(const ringbuffer_log &) = delete;
    //! No moving
    ringbuffer_log &operator=(ringbuffer_log &&) = delete;
    //! Swaps with another instance
    void swap(ringbuffer_log &o) noexcept
    {
      std::swap(_store, o._store);
      std::swap(_level, o._level);
      std::swap(_counter, o._counter);
      std::swap(_immediate, o._immediate);
    }

    //! Returns the current log level
    level log_level() const noexcept { return _level; }
    //! Returns the current log level
    void log_level(level new_level) noexcept { _level = new_level; }

    //! Returns true if the log is empty
    bool empty() const noexcept { return _counter.load(std::memory_order_relaxed) == 0; }
    //! Returns the number of items in the log
    size_type size() const noexcept
    {
      size_type ret = _counter.load(std::memory_order_relaxed);
      if(_store.size() < ret)
        ret = _store.size();
      return ret;
    }
    //! Returns the maximum number of items in the log
    size_type max_size() const noexcept { return max_items ? max_items : _store.size(); }
    //! Returns any `std::ostream` immediately printed to when a new log entry is added
    std::ostream *immediate() const noexcept { return _immediate; }
    //! Set any `std::ostream` immediately printed to when a new log entry is added
    void immediate(std::ostream *s) noexcept { _immediate = s; }

    //! Used to tag an index as being an absolute lookup of a unique counter value returned by push_back/emplace_back.
    struct unique_id
    {
      size_type value;
      constexpr unique_id(size_type _value)
          : value(_value)
      {
      }
    };
    //! True if a unique id is still valid
    bool valid(unique_id id) const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return id.value < counter && id.value >= counter - size;
    }

    //! Returns the front of the ringbuffer. Be careful of races with concurrent modifies.
    reference front() noexcept { return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1)]; }
    //! Returns the front of the ringbuffer. Be careful of races with concurrent modifies.
    const_reference front() const noexcept { return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1)]; }
#ifdef __cpp_exceptions
    //! Returns a reference to the specified element. Be careful of races with concurrent modifies.
    reference at(size_type pos)
    {
      if(pos >= size())
        throw std::out_of_range("index exceeds size");
      return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1 - pos)];
    }
    //! Returns a reference to the specified element.
    reference at(unique_id id)
    {
      if(!valid(id))
        throw std::out_of_range("index exceeds size");
      return _store[counter_to_idx(id.value)];
    }
    //! Returns a reference to the specified element. Be careful of races with concurrent modifies.
    const_reference at(size_type pos) const
    {
      if(pos >= size())
        throw std::out_of_range("index exceeds size");
      return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1 - pos)];
    }
    //! Returns a reference to the specified element.
    const_reference at(unique_id id) const
    {
      if(!valid(id))
        throw std::out_of_range("index exceeds size");
      return _store[counter_to_idx(id.value)];
    }
#endif
    //! Returns a reference to the specified element. Be careful of races with concurrent modifies.
    reference operator[](size_type pos) noexcept { return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1 - pos)]; }
    //! Returns a reference to the specified element.
    reference operator[](unique_id id) noexcept { return _store[counter_to_idx(id.value)]; }
    //! Returns a reference to the specified element. Be careful of races with concurrent modifies.
    const_reference operator[](size_type pos) const noexcept { return _store[counter_to_idx(_counter.load(std::memory_order_relaxed) - 1 - pos)]; }
    //! Returns a reference to the specified element.
    const_reference operator[](unique_id id) const noexcept { return _store[counter_to_idx(id.value)]; }
    //! Returns the back of the ringbuffer. Be careful of races with concurrent modifies.
    reference back() noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return _store[counter_to_idx(counter - size)];
    }
    //! Returns the back of the ringbuffer. Be careful of races with concurrent modifies.
    const_reference back() const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return _store[counter_to_idx(counter - size)];
    }

    //! Returns an iterator to the first item in the log. Be careful of races with concurrent modifies.
    iterator begin() noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return iterator(this, counter - 1, size);
    }
    //! Returns an iterator to the first item in the log. Be careful of races with concurrent modifies.
    const_iterator begin() const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return const_iterator(this, counter - 1, size);
    }
    //! Returns an iterator to the first item in the log. Be careful of races with concurrent modifies.
    const_iterator cbegin() const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return const_iterator(this, counter - 1, size);
    }
    //! Returns an iterator to the item after the last in the log. Be careful of races with concurrent modifies.
    iterator end() noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return iterator(this, counter - 1 - size, 0);
    }
    //! Returns an iterator to the item after the last in the log. Be careful of races with concurrent modifies.
    const_iterator end() const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return const_iterator(this, counter - 1 - size, 0);
    }
    //! Returns an iterator to the item after the last in the log. Be careful of races with concurrent modifies.
    const_iterator cend() const noexcept
    {
      size_type counter = _counter.load(std::memory_order_relaxed);
      size_type size = counter;
      if(_store.size() < size)
        size = _store.size();
      return const_iterator(this, counter - 1 - size, 0);
    }

    //! Clears the log
    void clear() noexcept
    {
      _counter.store(0, std::memory_order_relaxed);
      std::fill(_store.begin(), _store.end(), value_type());
    }
    //! THREADSAFE Logs a new item, returning its unique counter id
    size_type push_back(value_type &&v) noexcept
    {
      if(static_cast<level>(v.level) <= _level)
      {
        if(_immediate)
          *_immediate << v << std::endl;
        size_type thisitem = _counter++;
        v.counter = thisitem;
        _store[counter_to_idx(thisitem)] = std::move(v);
        return thisitem;
      }
      return (size_type) -1;
    }
    //! THREADSAFE Logs a new item, returning its unique counter id
    template <class... Args> size_type emplace_back(level __level, Args &&... args) noexcept
    {
      if(__level <= _level)
      {
        value_type v(__level, std::forward<Args>(args)...);
        if(_immediate)
          *_immediate << v << std::endl;
        size_type thisitem = _counter++;
        v.counter = thisitem;
        _store[counter_to_idx(thisitem)] = std::move(v);
        return thisitem;
      }
      return (size_type) -1;
    }
  };

  //! std::ostream writer for a log
  template <class Policy> inline std::ostream &operator<<(std::ostream &s, const ringbuffer_log<Policy> &l)
  {
    for(const auto &i : l)
    {
      s << i;
    }
    return s;
  }

  //! CSV string writer for a log
  template <class Policy> inline std::string csv(const ringbuffer_log<Policy> &l)
  {
    std::stringstream s;
    // timestamp,level,using_code64,using_backtrace,code0,code1,message,backtrace
    s << "timestamp,level,using_code64,using_backtrace,code0,code1,message,backtrace\n";
    for(const auto &i : l)
    {
      csv(s, i);
    }
    return s.str();
  }

  //! Alias for a simple ringbuffer log
  template <size_t Bytes = BOOSTLITE_RINGBUFFER_LOG_DEFAULT_ENTRIES * 256> using simple_ringbuffer_log = ringbuffer_log<simple_ringbuffer_log_policy<Bytes>>;
}

BOOSTLITE_NAMESPACE_END


//! Logs an item to the log with calling function name
#define BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION(log, level, message, code1, code2) (log).emplace_back((level), (message), (code1), (code2), __func__, __LINE__)
//! Logs an item to the log with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE(log, level, message, code1, code2) (log).emplace_back((level), (message), (code1), (code2), nullptr)

#ifndef BOOSTLITE_RINGBUFFERLOG_LEVEL
#if defined(_DEBUG) || defined(DEBUG)
#define BOOSTLITE_RINGBUFFERLOG_LEVEL 5  // debug
#else
#define BOOSTLITE_RINGBUFFERLOG_LEVEL 2  // error
#endif
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 1
//! Logs an item to the log at fatal level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_FATAL_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::fatal, (message), (code1), (code2))
//! Logs an item to the log at fatal level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_FATAL_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::fatal, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_FATAL_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_FATAL_BACKTRACE(log, message, code1, code2)
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 2
//! Logs an item to the log at error level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_ERROR_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::error, (message), (code1), (code2))
//! Logs an item to the log at error level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_ERROR_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::error, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_ERROR_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_ERROR_BACKTRACE(log, message, code1, code2)
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 3
//! Logs an item to the log at warn level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_WARN_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::warn, (message), (code1), (code2))
//! Logs an item to the log at warn level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_WARN_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::warn, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_WARN_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_WARN_BACKTRACE(log, message, code1, code2)
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 4
//! Logs an item to the log at info level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_INFO_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::info, (message), (code1), (code2))
//! Logs an item to the log at info level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_INFO_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::info, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_INFO_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_INFO_BACKTRACE(log, message, code1, code2)
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 5
//! Logs an item to the log at debug level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_DEBUG_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::debug, (message), (code1), (code2))
//! Logs an item to the log at debug level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_DEBUG_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::debug, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_DEBUG_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_DEBUG_BACKTRACE(log, message, code1, code2)
#endif

#if BOOSTLITE_RINGBUFFERLOG_LEVEL >= 6
//! Logs an item to the log at all level with calling function name
#define BOOSTLITE_RINGBUFFERLOG_ALL_FUNCTION(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_FUNCTION((log), ringbuffer_log::level::all, (message), (code1), (code2))
//! Logs an item to the log at all level with stack backtrace
#define BOOSTLITE_RINGBUFFERLOG_ALL_BACKTRACE(log, message, code1, code2) BOOSTLITE_RINGBUFFERLOG_ITEM_BACKTRACE((log), ringbuffer_log::level::all, (message), (code1), (code2))
#else
#define BOOSTLITE_RINGBUFFERLOG_ALL_FUNCTION(log, message, code1, code2)
#define BOOSTLITE_RINGBUFFERLOG_ALL_BACKTRACE(log, message, code1, code2)
#endif

#endif