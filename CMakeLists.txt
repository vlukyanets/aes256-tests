cmake_minimum_required(VERSION 3.13)
project(aes256_tests)

set(CMAKE_CXX_STANDARD 17)

add_executable(aes256-cbc-encrypt aes256-cbc-encrypt.cpp)
target_link_libraries(aes256-cbc-encrypt crypto)

add_executable(aes256-cbc-decrypt aes256-cbc-decrypt.cpp)
target_link_libraries(aes256-cbc-decrypt crypto)
