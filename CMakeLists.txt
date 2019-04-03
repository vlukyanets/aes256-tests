cmake_minimum_required(VERSION 3.13)
project(aes256_tests)

set(CMAKE_CXX_STANDARD 17)

add_executable(aes256_tests aes256-cbc-encrypt.cpp)

target_link_libraries(aes256_tests ssl)
