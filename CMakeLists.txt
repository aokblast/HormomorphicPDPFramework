cmake_minimum_required(VERSION 3.21)
project(HormomorphicHashChecker)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

find_package(SEAL 4.1.1 EXACT REQUIRED)
find_package(Boost 1.81.0)

SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -g ")
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall")


INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
INCLUDE_DIRECTORIES(./Hash)
INCLUDE_DIRECTORIES(./libtfhe/include /usr/local/include/)
INCLUDE_DIRECTORIES(./HashTree/include)


add_subdirectory(libtfhe)
add_subdirectory(HashTree)

add_executable(HormomorphicHashChecker main.cpp)
add_executable(Server Server/Server.cpp Server/Server.h Server/main.cpp common.h)
add_executable(Client Client/Client.cpp Client/Client.h Client/main.cpp common.h)
add_executable(SHA256Test Hash/SHA256.cpp Hash/SHA256Example.cpp)
add_executable(MD5Test Hash/MD5.cpp Hash/MD5Example.cpp)
add_executable(Hasher hasher.cpp)

target_link_libraries(HormomorphicHashChecker libhashtree)
target_link_libraries(HormomorphicHashChecker libtfhe tfhe-spqlios-avx)

target_link_libraries(Hasher libhashtree)
target_link_libraries(Hasher libtfhe tfhe-spqlios-avx)

target_link_libraries(Server SEAL::seal)
target_link_libraries(Server LINK_PUBLIC ${Boost_LIBRARIES})

target_link_libraries(Client SEAL::seal)
target_link_libraries(Client LINK_PUBLIC ${Boost_LIBRARIES})

target_link_libraries(SHA256Test libtfhe tfhe-spqlios-fma)
target_link_libraries(MD5Test libtfhe tfhe-spqlios-fma)