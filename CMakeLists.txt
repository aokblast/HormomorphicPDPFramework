cmake_minimum_required(VERSION 3.21)
project(HormomorphicHashChecker)

set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.1.1 EXACT REQUIRED)
find_package(Boost 1.81.0 EXACT REQUIRED)


INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
INCLUDE_DIRECTORIES(./Hash)
INCLUDE_DIRECTORIES( ./libtfhe/include /usr/local/include/)

add_subdirectory(libtfhe)
add_subdirectory(libtfhe_openfhe)

add_executable(HormomorphicHashChecker main.cpp Hash/SHA256.cpp Hash/SHA256.h)
add_executable(Server Server/Server.cpp Server/Server.h Server/main.cpp common.h)
add_executable(Client Client/Client.cpp Client/Client.h Client/main.cpp common.h)
add_executable(SHA256Test Hash/SHA256.cpp Hash/SHA256Example.cpp)
add_executable(MD5Test Hash/MD5.cpp Hash/MD5Example.cpp)

target_link_libraries(Server PRIVATE SEAL::seal)
target_link_libraries(Server LINK_PUBLIC ${Boost_LIBRARIES})

target_link_libraries(Client PRIVATE SEAL::seal)
target_link_libraries(Client LINK_PUBLIC ${Boost_LIBRARIES})

target_link_libraries(SHA256Test libtfhe tfhe-spqlios-avx)
target_link_libraries(MD5Test libtfhe tfhe-spqlios-avx)
