cmake_minimum_required (VERSION 2.6)

add_library(molch hkdf diffie-hellman key-derivation packet header header-and-message-keystore ratchet buffer user-store spiced-random molch)
target_link_libraries(molch ${libs})
