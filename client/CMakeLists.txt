cmake_minimum_required(VERSION 3.5)
project(ClientProject)

set(CMAKE_CXX_STANDARD 17)
find_package(Boost REQUIRED COMPONENTS system)
set(CRYPTOPP_ROOT /usr/local)
set(ZLIB_ROOT /usr/local/opt/zlib)  # Updated path for zlib
include_directories(${CRYPTOPP_ROOT}/include)
include_directories(${ZLIB_ROOT}/include)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(/usr/local/include)
include_directories(/usr/local/include/cryptopp)

# Add cksum_new.cpp to the list of source files
add_executable(client client.cpp encryption.cpp cksum_new.cpp)

target_link_libraries(client PRIVATE Boost::system)

find_library(CRYPTOPP_LIB cryptopp HINTS ${CRYPTOPP_ROOT}/lib)
if(NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ library not found")
endif()
target_link_libraries(client PRIVATE ${CRYPTOPP_LIB})

find_library(ZLIB_LIB z HINTS ${ZLIB_ROOT}/lib)
if(NOT ZLIB_LIB)
    message(FATAL_ERROR "zlib library not found")
endif()
target_link_libraries(client PRIVATE ${ZLIB_LIB})
