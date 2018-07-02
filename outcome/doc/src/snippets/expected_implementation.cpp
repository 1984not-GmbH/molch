#include "../../../include/outcome/outcome.hpp"

#if(_HAS_CXX17 || __cplusplus >= 201700)
//! [expected_implementation]
/* Here is a fairly conforming implementation of P0323R3 `expected<T, E>` using `checked<T, E>`.
It passes the reference test suite for P0323R3 at
https://github.com/viboes/std-make/blob/master/test/expected/expected_pass.cpp with modifications
only to move the test much closer to the P0323R3 Expected, as the reference test suite is for a
much older proposed Expected.

Known differences from P0323R3 in this implementation:
- `T` and `E` cannot be the same type.
- `E` must be default constructible.
- No variant storage is implemented (note the Expected proposal does not actually require this).
*/

namespace detail
{
  template <class T, class E> using expected_result = OUTCOME_V2_NAMESPACE::checked<T, E>;
  template <class T, class E> struct enable_default_constructor : public expected_result<T, E>
  {
    using base = expected_result<T, E>;
    using base::base;
    constexpr enable_default_constructor()
        : base{OUTCOME_V2_NAMESPACE::in_place_type<T>}
    {
    }
  };
  template <class T, class E> using select_expected_base = std::conditional_t<std::is_default_constructible<T>::value, enable_default_constructor<T, E>, expected_result<T, E>>;
}
template <class T, class E> class expected : public detail::select_expected_base<T, E>
{
  static_assert(!std::is_same<T, E>::value, "T and E cannot be the same in this expected implementation");
  using base = detail::select_expected_base<T, E>;

public:
  // Inherit base's constructors
  using base::base;
  expected() = default;

  // Expected takes in_place not in_place_type
  template <class... Args>
  constexpr explicit expected(std::in_place_t /*unused*/, Args &&... args)
      : base{OUTCOME_V2_NAMESPACE::in_place_type<T>, std::forward<Args>(args)...}
  {
  }

  // Expected always accepts a T even if ambiguous
  OUTCOME_TEMPLATE(class U)
  OUTCOME_TREQUIRES(OUTCOME_TPRED(std::is_constructible<T, U>::value))
  constexpr expected(U &&v)
      : base{OUTCOME_V2_NAMESPACE::in_place_type<T>, std::forward<U>(v)}
  {
  }

  // Expected has an emplace() modifier
  template <class... Args> void emplace(Args &&... args) { *static_cast<base *>(this) = base{OUTCOME_V2_NAMESPACE::in_place_type<T>, std::forward<Args>(args)...}; }

  // Expected has a narrow operator* and operator->
  constexpr const T &operator*() const & { return base::assume_value(); }
  constexpr T &operator*() & { return base::assume_value(); }
  constexpr const T &&operator*() const && { return base::assume_value(); }
  constexpr T &&operator*() && { return base::assume_value(); }
  constexpr const T *operator->() const { return &base::assume_value(); }
  constexpr T *operator->() { return &base::assume_value(); }

  // Expected has a narrow error() observer
  constexpr const E &error() const & { return base::assume_error(); }
  constexpr E &error() & { return base::assume_error(); }
  constexpr const E &&error() const && { return base::assume_error(); }
  constexpr E &error() && { return base::assume_error(); }
};
template <class E> class expected<void, E> : public OUTCOME_V2_NAMESPACE::result<void, E, OUTCOME_V2_NAMESPACE::policy::throw_bad_result_access<E>>
{
  using base = OUTCOME_V2_NAMESPACE::result<void, E, OUTCOME_V2_NAMESPACE::policy::throw_bad_result_access<E>>;

public:
  // Inherit base constructors
  using base::base;

  // Expected has a narrow operator* and operator->
  constexpr void operator*() const { base::assume_value(); }
  constexpr void operator->() const { base::assume_value(); }
};
template <class E> using unexpected = OUTCOME_V2_NAMESPACE::failure_type<E>;
template <class E> unexpected<E> make_unexpected(E &&arg)
{
  return OUTCOME_V2_NAMESPACE::failure<E>(std::forward<E>(arg));
}
template <class E, class... Args> unexpected<E> make_unexpected(Args &&... args)
{
  return OUTCOME_V2_NAMESPACE::failure<E>(std::forward<Args>(args)...);
}
template <class E> using bad_expected_access = OUTCOME_V2_NAMESPACE::bad_result_access_with<E>;
//! [expected_implementation]
#endif

int main()
{
  return 0;
}
