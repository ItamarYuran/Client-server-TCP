cmake_minimum_required(VERSION 3.5)
project(ClientProject)

set(CMAKE_CXX_STANDARD 11)

# Add the Boost library dependency
find_package(Boost REQUIRED COMPONENTS system)

# Set the path to Crypto++ root directory (if not installed in a standard location)
set(CRYPTOPP_ROOT /usr/local)

# Set the path to zlib root directory (if not installed in a standard location)
set(ZLIB_ROOT /usr/local/opt/zlib)  # Updated path for zlib

# Include the Crypto++ headers
include_directories(${CRYPTOPP_ROOT}/include)

# Include the zlib headers
include_directories(${ZLIB_ROOT}/include)

# Include directories for Boost and the current directory
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Include directories for Crypto++
include_directories(/usr/local/include)
include_directories(/usr/local/include/cryptopp)

# Add the executable target
add_executable(client client.cpp client_menu.cpp encryption.cpp)

# Link the Boost library
target_link_libraries(client PRIVATE Boost::system)

# Link the Crypto++ library
find_library(CRYPTOPP_LIB cryptopp HINTS ${CRYPTOPP_ROOT}/lib)
if(NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ library not found")
endif()
target_link_libraries(client PRIVATE ${CRYPTOPP_LIB})

# Link zlib
find_library(ZLIB_LIB z HINTS ${ZLIB_ROOT}/lib)
if(NOT ZLIB_LIB)
    message(FATAL_ERROR "zlib library not found")
endif()
target_link_libraries(client PRIVATE ${ZLIB_LIB})
