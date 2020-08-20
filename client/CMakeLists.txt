cmake_minimum_required(VERSION 3.17)
project(client)

set(CMAKE_CXX_STANDARD 17)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE lib cppzmq cppzmq-static nlohmann_json
        nlohmann_json::nlohmann_json magic_enum::magic_enum OpenSSL::SSL OpenSSL::Crypto)
