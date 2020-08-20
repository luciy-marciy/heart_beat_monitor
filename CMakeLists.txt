cmake_minimum_required(VERSION 3.17)
project(heart_beat_monitor)

find_package(cppzmq CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(magic_enum REQUIRED)
find_package(OpenSSL REQUIRED)

add_subdirectory(lib)
add_subdirectory(server)
add_subdirectory(client)

set(CMAKE_CXX_STANDARD 17)

add_executable(DeepGrayResearch main.cpp)
target_link_libraries(DeepGrayResearch PRIVATE lib  OpenSSL::SSL OpenSSL::Crypto)
#target_include_directories(DeepGrayResearch PUBLIC include)
install(TARGETS server client DESTINATION ${CMAKE_SOURCE_DIR}/build)