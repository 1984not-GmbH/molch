/*
 * \file Loads the CPP Core Guidelines support libraries and configures it's behavior.
 */

#ifndef LIB_GSL_HPP
#define LIB_GSL_HPP

#define GSL_THROW_ON_CONTRACT_VIOLATION //throw exception when contract is violated (instead of std::terminate)!
#include <gsl/gsl_assert>
#include <gsl/gsl_byte>
#include <gsl/span>

namespace Molch {
	inline unsigned char* byte_to_uchar(std::byte* byte) {
		return reinterpret_cast<unsigned char*>(byte);
	}

	inline const unsigned char* byte_to_uchar(const std::byte* byte) {
		return reinterpret_cast<const unsigned char*>(byte);
	}

	constexpr unsigned char byte_to_uchar(const std::byte byte) {
		return static_cast<unsigned char>(byte);
	}

	inline std::byte* uchar_to_byte(unsigned char* character) {
		return reinterpret_cast<std::byte*>(character);
	}

	inline const std::byte* uchar_to_byte(const unsigned char* character) {
		return reinterpret_cast<const std::byte*>(character);
	}

	constexpr std::byte uchar_to_byte(const unsigned char character) {
		return static_cast<std::byte>(character);
	}

	template <class ElementType>
	class span : public gsl::span<ElementType> {
	private:
		using base_class = gsl::span<ElementType>;

	public:
		//make base class constructors available
		using base_class::base_class;

		constexpr span() : base_class{nullptr, static_cast<ptrdiff_t>(0)} {}

		constexpr span(ElementType* pointer, size_t count)
			: base_class{pointer, gsl::narrow<ptrdiff_t>(count)} {}

		constexpr span(gsl::span<ElementType> gsl_span) : base_class{gsl_span} {}

		constexpr size_t size() const {
			return gsl::narrow<size_t>(this->base_class::size());
		}
	};
}

#endif /* LIB_GSL_HPP */
