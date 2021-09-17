cmake_minimum_required(VERSION 3.20)
project(AnjayTest C)

set(CMAKE_C_STANDARD 99)

find_package(anjay)
include_directories(${ANJAY_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} PRIVATE anjay)