# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

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
CMAKE_COMMAND = /snap/clion/163/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/163/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/AnjayTest.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/AnjayTest.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/AnjayTest.dir/flags.make

CMakeFiles/AnjayTest.dir/main.c.o: CMakeFiles/AnjayTest.dir/flags.make
CMakeFiles/AnjayTest.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/AnjayTest.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/AnjayTest.dir/main.c.o -c /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/main.c

CMakeFiles/AnjayTest.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/AnjayTest.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/main.c > CMakeFiles/AnjayTest.dir/main.c.i

CMakeFiles/AnjayTest.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/AnjayTest.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/main.c -o CMakeFiles/AnjayTest.dir/main.c.s

# Object files for target AnjayTest
AnjayTest_OBJECTS = \
"CMakeFiles/AnjayTest.dir/main.c.o"

# External object files for target AnjayTest
AnjayTest_EXTERNAL_OBJECTS =

AnjayTest: CMakeFiles/AnjayTest.dir/main.c.o
AnjayTest: CMakeFiles/AnjayTest.dir/build.make
AnjayTest: /usr/local/lib/libanjay.a
AnjayTest: /usr/local/lib/libavs_coap.a
AnjayTest: /usr/local/lib/libavs_algorithm.a
AnjayTest: /usr/local/lib/libavs_net_mbedtls.a
AnjayTest: /usr/local/lib/libavs_crypto_mbedtls.a
AnjayTest: /usr/lib/x86_64-linux-gnu/libmbedtls.so
AnjayTest: /usr/lib/x86_64-linux-gnu/libmbedx509.so
AnjayTest: /usr/lib/x86_64-linux-gnu/libmbedcrypto.so
AnjayTest: /usr/local/lib/libavs_sched.a
AnjayTest: /usr/local/lib/libavs_stream_net.a
AnjayTest: /usr/local/lib/libavs_url.a
AnjayTest: /usr/local/lib/libavs_persistence.a
AnjayTest: /usr/local/lib/libavs_rbtree.a
AnjayTest: /usr/local/lib/libavs_stream.a
AnjayTest: /usr/local/lib/libavs_buffer.a
AnjayTest: /usr/local/lib/libavs_list.a
AnjayTest: /usr/local/lib/libavs_utils.a
AnjayTest: /usr/local/lib/libavs_compat_threading_pthread.a
AnjayTest: /usr/local/lib/libavs_log.a
AnjayTest: /usr/local/lib/libavs_list.a
AnjayTest: /usr/local/lib/libavs_utils.a
AnjayTest: /usr/local/lib/libavs_compat_threading_pthread.a
AnjayTest: /usr/local/lib/libavs_log.a
AnjayTest: CMakeFiles/AnjayTest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable AnjayTest"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/AnjayTest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/AnjayTest.dir/build: AnjayTest
.PHONY : CMakeFiles/AnjayTest.dir/build

CMakeFiles/AnjayTest.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/AnjayTest.dir/cmake_clean.cmake
.PHONY : CMakeFiles/AnjayTest.dir/clean

CMakeFiles/AnjayTest.dir/depend:
	cd /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug /home/daniel/Documents/Vention/ClionWorkspace/AnjayTest/cmake-build-debug/CMakeFiles/AnjayTest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/AnjayTest.dir/depend

