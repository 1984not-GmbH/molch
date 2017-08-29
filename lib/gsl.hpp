/*
 * \file Loads the CPP Core Guidelines support libraries and configures it's behavior.
 */

#ifndef LIB_GSL_HPP
#define LIB_GSL_HPP

#define GSL_THROW_ON_CONTRACT_VIOLATION //throw exception when contract is violated (instead of std::terminate)!
#include <gsl/gsl>

inline unsigned char* byte_to_uchar(gsl::byte* byte) {
	return reinterpret_cast<unsigned char*>(byte);
}

inline const unsigned char* byte_to_uchar(const gsl::byte* byte) {
	return reinterpret_cast<const unsigned char*>(byte);
}

constexpr unsigned char byte_to_uchar(const gsl::byte byte) {
	return static_cast<unsigned char>(byte);
}

inline gsl::byte* uchar_to_byte(unsigned char* character) {
	return reinterpret_cast<gsl::byte*>(character);
}

inline const gsl::byte* uchar_to_byte(const unsigned char* character) {
	return reinterpret_cast<const gsl::byte*>(character);
}

constexpr gsl::byte uchar_to_byte(const unsigned char character) {
	return static_cast<gsl::byte>(character);
}

inline size_t narrow(ptrdiff_t size) {
	return gsl::narrow<size_t>(size);
}

inline ptrdiff_t narrow(size_t size) {
	return gsl::narrow<ptrdiff_t>(size);
}

#endif /* LIB_GSL_HPP */
