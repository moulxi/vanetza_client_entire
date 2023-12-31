# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/vanetza/桌面/vanetza_IEEE/vanetza-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build

# Include any dependencies generated for this target.
include tools/certify/CMakeFiles/certify.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tools/certify/CMakeFiles/certify.dir/compiler_depend.make

# Include the progress variables for this target.
include tools/certify/CMakeFiles/certify.dir/progress.make

# Include the compile flags for this target's objects.
include tools/certify/CMakeFiles/certify.dir/flags.make

tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o: ../tools/certify/commands/extract-public-key.cpp
tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o -MF CMakeFiles/certify.dir/commands/extract-public-key.cpp.o.d -o CMakeFiles/certify.dir/commands/extract-public-key.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/extract-public-key.cpp

tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/extract-public-key.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/extract-public-key.cpp > CMakeFiles/certify.dir/commands/extract-public-key.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/extract-public-key.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/extract-public-key.cpp -o CMakeFiles/certify.dir/commands/extract-public-key.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o: ../tools/certify/commands/generate-aa.cpp
tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o -MF CMakeFiles/certify.dir/commands/generate-aa.cpp.o.d -o CMakeFiles/certify.dir/commands/generate-aa.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-aa.cpp

tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/generate-aa.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-aa.cpp > CMakeFiles/certify.dir/commands/generate-aa.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/generate-aa.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-aa.cpp -o CMakeFiles/certify.dir/commands/generate-aa.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o: ../tools/certify/commands/generate-key.cpp
tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o -MF CMakeFiles/certify.dir/commands/generate-key.cpp.o.d -o CMakeFiles/certify.dir/commands/generate-key.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-key.cpp

tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/generate-key.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-key.cpp > CMakeFiles/certify.dir/commands/generate-key.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/generate-key.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-key.cpp -o CMakeFiles/certify.dir/commands/generate-key.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o: ../tools/certify/commands/generate-root.cpp
tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o -MF CMakeFiles/certify.dir/commands/generate-root.cpp.o.d -o CMakeFiles/certify.dir/commands/generate-root.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-root.cpp

tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/generate-root.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-root.cpp > CMakeFiles/certify.dir/commands/generate-root.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/generate-root.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-root.cpp -o CMakeFiles/certify.dir/commands/generate-root.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o: ../tools/certify/commands/generate-ticket.cpp
tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o -MF CMakeFiles/certify.dir/commands/generate-ticket.cpp.o.d -o CMakeFiles/certify.dir/commands/generate-ticket.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-ticket.cpp

tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/generate-ticket.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-ticket.cpp > CMakeFiles/certify.dir/commands/generate-ticket.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/generate-ticket.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/generate-ticket.cpp -o CMakeFiles/certify.dir/commands/generate-ticket.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o: ../tools/certify/commands/show-certificate.cpp
tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o -MF CMakeFiles/certify.dir/commands/show-certificate.cpp.o.d -o CMakeFiles/certify.dir/commands/show-certificate.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/show-certificate.cpp

tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/show-certificate.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/show-certificate.cpp > CMakeFiles/certify.dir/commands/show-certificate.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/show-certificate.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/show-certificate.cpp -o CMakeFiles/certify.dir/commands/show-certificate.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o: ../tools/certify/commands/validation.cpp
tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o -MF CMakeFiles/certify.dir/commands/validation.cpp.o.d -o CMakeFiles/certify.dir/commands/validation.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/validation.cpp

tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/validation.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/validation.cpp > CMakeFiles/certify.dir/commands/validation.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/validation.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/validation.cpp -o CMakeFiles/certify.dir/commands/validation.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o: ../tools/certify/commands/client.cpp
tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o -MF CMakeFiles/certify.dir/commands/client.cpp.o.d -o CMakeFiles/certify.dir/commands/client.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/client.cpp

tools/certify/CMakeFiles/certify.dir/commands/client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/client.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/client.cpp > CMakeFiles/certify.dir/commands/client.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/client.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/client.cpp -o CMakeFiles/certify.dir/commands/client.cpp.s

tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o: ../tools/certify/commands/server.cpp
tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o -MF CMakeFiles/certify.dir/commands/server.cpp.o.d -o CMakeFiles/certify.dir/commands/server.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/server.cpp

tools/certify/CMakeFiles/certify.dir/commands/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/commands/server.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/server.cpp > CMakeFiles/certify.dir/commands/server.cpp.i

tools/certify/CMakeFiles/certify.dir/commands/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/commands/server.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/commands/server.cpp -o CMakeFiles/certify.dir/commands/server.cpp.s

tools/certify/CMakeFiles/certify.dir/main.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/main.cpp.o: ../tools/certify/main.cpp
tools/certify/CMakeFiles/certify.dir/main.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object tools/certify/CMakeFiles/certify.dir/main.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/main.cpp.o -MF CMakeFiles/certify.dir/main.cpp.o.d -o CMakeFiles/certify.dir/main.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/main.cpp

tools/certify/CMakeFiles/certify.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/main.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/main.cpp > CMakeFiles/certify.dir/main.cpp.i

tools/certify/CMakeFiles/certify.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/main.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/main.cpp -o CMakeFiles/certify.dir/main.cpp.s

tools/certify/CMakeFiles/certify.dir/options.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/options.cpp.o: ../tools/certify/options.cpp
tools/certify/CMakeFiles/certify.dir/options.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object tools/certify/CMakeFiles/certify.dir/options.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/options.cpp.o -MF CMakeFiles/certify.dir/options.cpp.o.d -o CMakeFiles/certify.dir/options.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/options.cpp

tools/certify/CMakeFiles/certify.dir/options.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/options.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/options.cpp > CMakeFiles/certify.dir/options.cpp.i

tools/certify/CMakeFiles/certify.dir/options.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/options.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/options.cpp -o CMakeFiles/certify.dir/options.cpp.s

tools/certify/CMakeFiles/certify.dir/utils.cpp.o: tools/certify/CMakeFiles/certify.dir/flags.make
tools/certify/CMakeFiles/certify.dir/utils.cpp.o: ../tools/certify/utils.cpp
tools/certify/CMakeFiles/certify.dir/utils.cpp.o: tools/certify/CMakeFiles/certify.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object tools/certify/CMakeFiles/certify.dir/utils.cpp.o"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tools/certify/CMakeFiles/certify.dir/utils.cpp.o -MF CMakeFiles/certify.dir/utils.cpp.o.d -o CMakeFiles/certify.dir/utils.cpp.o -c /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/utils.cpp

tools/certify/CMakeFiles/certify.dir/utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/certify.dir/utils.cpp.i"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/utils.cpp > CMakeFiles/certify.dir/utils.cpp.i

tools/certify/CMakeFiles/certify.dir/utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/certify.dir/utils.cpp.s"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify/utils.cpp -o CMakeFiles/certify.dir/utils.cpp.s

# Object files for target certify
certify_OBJECTS = \
"CMakeFiles/certify.dir/commands/extract-public-key.cpp.o" \
"CMakeFiles/certify.dir/commands/generate-aa.cpp.o" \
"CMakeFiles/certify.dir/commands/generate-key.cpp.o" \
"CMakeFiles/certify.dir/commands/generate-root.cpp.o" \
"CMakeFiles/certify.dir/commands/generate-ticket.cpp.o" \
"CMakeFiles/certify.dir/commands/show-certificate.cpp.o" \
"CMakeFiles/certify.dir/commands/validation.cpp.o" \
"CMakeFiles/certify.dir/commands/client.cpp.o" \
"CMakeFiles/certify.dir/commands/server.cpp.o" \
"CMakeFiles/certify.dir/main.cpp.o" \
"CMakeFiles/certify.dir/options.cpp.o" \
"CMakeFiles/certify.dir/utils.cpp.o"

# External object files for target certify
certify_EXTERNAL_OBJECTS =

bin/certify: tools/certify/CMakeFiles/certify.dir/commands/extract-public-key.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/generate-aa.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/generate-key.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/generate-root.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/generate-ticket.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/show-certificate.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/validation.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/client.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/commands/server.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/main.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/options.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/utils.cpp.o
bin/certify: tools/certify/CMakeFiles/certify.dir/build.make
bin/certify: /usr/lib/x86_64-linux-gnu/libboost_program_options.so.1.74.0
bin/certify: lib/static/libvanetza_asn1_security.a
bin/certify: lib/static/libvanetza_asn1_pki.a
bin/certify: lib/static/libvanetza_btp.a
bin/certify: lib/static/libvanetza_facilities.a
bin/certify: lib/static/libvanetza_asn1.a
bin/certify: lib/static/libvanetza_asn1_its.a
bin/certify: lib/static/libvanetza_asn1_support.a
bin/certify: lib/static/libvanetza_geonet.a
bin/certify: lib/static/libvanetza_dcc.a
bin/certify: lib/static/libvanetza_access.a
bin/certify: lib/static/libvanetza_gnss.a
bin/certify: lib/static/libvanetza_security.a
bin/certify: lib/static/libvanetza_net.a
bin/certify: lib/static/libvanetza_common.a
bin/certify: /usr/lib/x86_64-linux-gnu/libboost_date_time.so.1.74.0
bin/certify: /usr/lib/x86_64-linux-gnu/libGeographic.so
bin/certify: /usr/lib/x86_64-linux-gnu/libcryptopp.so
bin/certify: tools/certify/CMakeFiles/certify.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Linking CXX executable ../../bin/certify"
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/certify.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tools/certify/CMakeFiles/certify.dir/build: bin/certify
.PHONY : tools/certify/CMakeFiles/certify.dir/build

tools/certify/CMakeFiles/certify.dir/clean:
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify && $(CMAKE_COMMAND) -P CMakeFiles/certify.dir/cmake_clean.cmake
.PHONY : tools/certify/CMakeFiles/certify.dir/clean

tools/certify/CMakeFiles/certify.dir/depend:
	cd /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/vanetza/桌面/vanetza_IEEE/vanetza-master /home/vanetza/桌面/vanetza_IEEE/vanetza-master/tools/certify /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify /home/vanetza/桌面/vanetza_IEEE/vanetza-master/build/tools/certify/CMakeFiles/certify.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tools/certify/CMakeFiles/certify.dir/depend

