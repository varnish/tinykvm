cmake_minimum_required(VERSION 3.16)
project(tinykvm CXX)

option(FLTO "Link-time optimizations" OFF)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2 -g -march=native")

if (FLTO)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=thin")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
endif()


add_subdirectory(lib tinykvm)

add_executable(bench
	src/bench.cpp
	src/functions.cpp
)
target_link_libraries(bench tinykvm)

add_executable(tinytest
	src/tests.cpp
	src/functions.cpp
)
target_link_libraries(tinytest tinykvm)
