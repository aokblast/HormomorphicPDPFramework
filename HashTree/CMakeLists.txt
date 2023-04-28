cmake_minimum_required(VERSION 3.11)

project(libhashtree)
set(CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB SRC_FILES CONFIGURE_DEPENDS src/*.cpp)

add_library(libhashtree STATIC ${SRC_FILES} ${TFHE_BASE_DIR} ../Hash/MD5.cpp ../Hash/SHA256.cpp)