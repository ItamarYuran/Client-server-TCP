# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.28.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.28.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/Users/itamaryuran/Desktop/School/Defensive programming /project/client"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/Users/itamaryuran/Desktop/School/Defensive programming /project/client"

# Include any dependencies generated for this target.
include CMakeFiles/boost_logging_example.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/boost_logging_example.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/boost_logging_example.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/boost_logging_example.dir/flags.make

CMakeFiles/boost_logging_example.dir/c.cpp.o: CMakeFiles/boost_logging_example.dir/flags.make
CMakeFiles/boost_logging_example.dir/c.cpp.o: c.cpp
CMakeFiles/boost_logging_example.dir/c.cpp.o: CMakeFiles/boost_logging_example.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/Users/itamaryuran/Desktop/School/Defensive programming /project/client/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/boost_logging_example.dir/c.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/boost_logging_example.dir/c.cpp.o -MF CMakeFiles/boost_logging_example.dir/c.cpp.o.d -o CMakeFiles/boost_logging_example.dir/c.cpp.o -c "/Users/itamaryuran/Desktop/School/Defensive programming /project/client/c.cpp"

CMakeFiles/boost_logging_example.dir/c.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/boost_logging_example.dir/c.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/itamaryuran/Desktop/School/Defensive programming /project/client/c.cpp" > CMakeFiles/boost_logging_example.dir/c.cpp.i

CMakeFiles/boost_logging_example.dir/c.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/boost_logging_example.dir/c.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/itamaryuran/Desktop/School/Defensive programming /project/client/c.cpp" -o CMakeFiles/boost_logging_example.dir/c.cpp.s

# Object files for target boost_logging_example
boost_logging_example_OBJECTS = \
"CMakeFiles/boost_logging_example.dir/c.cpp.o"

# External object files for target boost_logging_example
boost_logging_example_EXTERNAL_OBJECTS =

boost_logging_example: CMakeFiles/boost_logging_example.dir/c.cpp.o
boost_logging_example: CMakeFiles/boost_logging_example.dir/build.make
boost_logging_example: /usr/local/Cellar/boost/1.84.0_1/lib/libboost_log-mt.dylib
boost_logging_example: /usr/local/Cellar/boost/1.84.0_1/lib/libboost_chrono-mt.dylib
boost_logging_example: /usr/local/Cellar/boost/1.84.0_1/lib/libboost_filesystem-mt.dylib
boost_logging_example: /usr/local/Cellar/boost/1.84.0_1/lib/libboost_atomic-mt.dylib
boost_logging_example: /usr/local/Cellar/boost/1.84.0_1/lib/libboost_thread-mt.dylib
boost_logging_example: CMakeFiles/boost_logging_example.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir="/Users/itamaryuran/Desktop/School/Defensive programming /project/client/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable boost_logging_example"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/boost_logging_example.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/boost_logging_example.dir/build: boost_logging_example
.PHONY : CMakeFiles/boost_logging_example.dir/build

CMakeFiles/boost_logging_example.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/boost_logging_example.dir/cmake_clean.cmake
.PHONY : CMakeFiles/boost_logging_example.dir/clean

CMakeFiles/boost_logging_example.dir/depend:
	cd "/Users/itamaryuran/Desktop/School/Defensive programming /project/client" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/Users/itamaryuran/Desktop/School/Defensive programming /project/client" "/Users/itamaryuran/Desktop/School/Defensive programming /project/client" "/Users/itamaryuran/Desktop/School/Defensive programming /project/client" "/Users/itamaryuran/Desktop/School/Defensive programming /project/client" "/Users/itamaryuran/Desktop/School/Defensive programming /project/client/CMakeFiles/boost_logging_example.dir/DependInfo.cmake" "--color=$(COLOR)"
.PHONY : CMakeFiles/boost_logging_example.dir/depend

