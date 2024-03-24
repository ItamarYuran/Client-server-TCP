cmake_minimum_required(VERSION 3.5)
project(ClientProject)

set(CMAKE_CXX_STANDARD 11)

# Add the Boost library dependency
find_package(Boost REQUIRED COMPONENTS system)

# Find Crypto++
find_package(cryptopp REQUIRED)

# Include directories for Boost, Crypto++, and the current directory
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CRYPTOPP_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add the executable target
add_executable(client client.cpp client_menu.cpp encryption.cpp)

# Link the Boost and Crypto++ libraries
target_link_libraries(client ${Boost_LIBRARIES} ${CRYPTOPP_LIBRARIES})
