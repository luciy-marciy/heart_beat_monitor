cmake_minimum_required(VERSION 3.17)
project(server)

set(CMAKE_CXX_STANDARD 17)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE lib cppzmq cppzmq-static)