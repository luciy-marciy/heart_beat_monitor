cmake_minimum_required(VERSION 3.17)
project(lib)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} STATIC src/crypto.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
