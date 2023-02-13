cmake_minimum_required(VERSION 3.11)

project(libtfhe)
set(CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/include /usr/local/include/)
set(TFHE_BASE_DIR /usr/local/lib)

file(GLOB SRC_FILES CONFIGURE_DEPENDS src/*.cpp)

add_library(libtfhe STATIC ${SRC_FILES} ${TFHE_BASE_DIR})

add_executable(libtfhe_test example/libtfhe_test.cpp)
target_link_libraries(libtfhe_test libtfhe tfhe-spqlios-fma)
